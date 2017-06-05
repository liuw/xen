/******************************************************************************
 * arch/x86/pv/traps.c
 *
 * PV low level entry points.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/trace.h>

#include <asm/apic.h>
#include <asm/shared.h>
#include <asm/traps.h>

void do_entry_int82(struct cpu_user_regs *regs)
{
    if ( unlikely(untrusted_msi) )
        check_for_unexpected_msi((uint8_t)regs->entry_vector);

    pv_hypercall(regs);
}

long do_set_trap_table(XEN_GUEST_HANDLE_PARAM(const_trap_info_t) traps)
{
    struct trap_info cur;
    struct vcpu *curr = current;
    struct trap_info *dst = curr->arch.pv_vcpu.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, NR_VECTORS * sizeof(*dst));
        init_int80_direct_trap(curr);
        return 0;
    }

    for ( ; ; )
    {
        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        if ( !is_canonical_address(cur.address) )
            return -EINVAL;

        fixup_guest_code_selector(curr->domain, cur.cs);

        memcpy(&dst[cur.vector], &cur, sizeof(cur));

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(curr);

        guest_handle_add_offset(traps, 1);

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }
    }

    return rc;
}

void pv_inject_event(const struct x86_event *event)
{
    struct vcpu *curr = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct trap_bounce *tb;
    const struct trap_info *ti;
    const uint8_t vector = event->vector;
    unsigned int error_code = event->error_code;
    bool use_error_code;

    ASSERT(vector == event->vector); /* Confirm no truncation. */
    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION )
    {
        ASSERT(vector < 32);
        use_error_code = TRAP_HAVE_EC & (1u << vector);
    }
    else
    {
        ASSERT(event->type == X86_EVENTTYPE_SW_INTERRUPT);
        use_error_code = false;
    }
    if ( use_error_code )
        ASSERT(error_code != X86_EVENT_NO_EC);
    else
        ASSERT(error_code == X86_EVENT_NO_EC);

    tb = &curr->arch.pv_vcpu.trap_bounce;
    ti = &curr->arch.pv_vcpu.trap_ctxt[vector];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION &&
         vector == TRAP_page_fault )
    {
        curr->arch.pv_vcpu.ctrlreg[2] = event->cr2;
        arch_set_cr2(curr, event->cr2);

        /* Re-set error_code.user flag appropriately for the guest. */
        error_code &= ~PFEC_user_mode;
        if ( !guest_kernel_mode(curr, regs) )
            error_code |= PFEC_user_mode;

        trace_pv_page_fault(event->cr2, error_code);
    }
    else
        trace_pv_trap(vector, regs->rip, use_error_code, error_code);

    if ( use_error_code )
    {
        tb->flags |= TBF_EXCEPTION_ERRCODE;
        tb->error_code = error_code;
    }

    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;

    if ( unlikely(null_trap_bounce(curr, tb)) )
    {
        gprintk(XENLOG_WARNING,
                "Unhandled %s fault/trap [#%d, ec=%04x]\n",
                trapstr(vector), vector, error_code);

        if ( vector == TRAP_page_fault )
            show_page_walk(event->cr2);
    }
}

/*
 * Called from asm to set up the MCE trapbounce info.
 * Returns false no callback is set up, else true.
 */
bool set_guest_machinecheck_trapbounce(void)
{
    struct vcpu *curr = current;
    struct trap_bounce *tb = &curr->arch.pv_vcpu.trap_bounce;

    pv_inject_hw_exception(TRAP_machine_check, X86_EVENT_NO_EC);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for MCE delivery path */
    return !null_trap_bounce(curr, tb);
}

/*
 * Called from asm to set up the NMI trapbounce info.
 * Returns false if no callback is set up, else true.
 */
bool set_guest_nmi_trapbounce(void)
{
    struct vcpu *curr = current;
    struct trap_bounce *tb = &curr->arch.pv_vcpu.trap_bounce;
    pv_inject_hw_exception(TRAP_nmi, X86_EVENT_NO_EC);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for NMI delivery path */
    return !null_trap_bounce(curr, tb);
}

long register_guest_nmi_callback(unsigned long address)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    struct trap_info *t = &curr->arch.pv_vcpu.trap_ctxt[TRAP_nmi];

    if ( !is_canonical_address(address) )
        return -EINVAL;

    t->vector  = TRAP_nmi;
    t->flags   = 0;
    t->cs      = (is_pv_32bit_domain(d) ?
                  FLAT_COMPAT_KERNEL_CS : FLAT_KERNEL_CS);
    t->address = address;
    TI_SET_IF(t, 1);

    /*
     * If no handler was registered we can 'lose the NMI edge'. Re-assert it
     * now.
     */
    if ( (curr->vcpu_id == 0) && (arch_get_nmi_reason(d) != 0) )
        curr->nmi_pending = 1;

    return 0;
}

long unregister_guest_nmi_callback(void)
{
    struct vcpu *curr = current;
    struct trap_info *t = &curr->arch.pv_vcpu.trap_ctxt[TRAP_nmi];

    memset(t, 0, sizeof(*t));

    return 0;
}

bool guest_has_trap_callback(const struct domain *d, unsigned int vcpuid,
                             unsigned int trap_nr)
{
    const struct vcpu *v;
    const struct trap_info *t;

    BUG_ON(d == NULL);
    BUG_ON(vcpuid >= d->max_vcpus);

    /* Sanity check - XXX should be more fine grained. */
    BUG_ON(trap_nr >= NR_VECTORS);

    v = d->vcpu[vcpuid];
    t = &v->arch.pv_vcpu.trap_ctxt[trap_nr];

    return t->address;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
