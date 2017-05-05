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
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/trace.h>

#include <asm/apic.h>
#include <asm/debugreg.h>
#include <asm/nmi.h>
#include <asm/shared.h>
#include <asm/traps.h>

void do_entry_int82(struct cpu_user_regs *regs)
{
    if ( unlikely(untrusted_msi) )
        check_for_unexpected_msi((uint8_t)regs->entry_vector);

    pv_hypercall(regs);
}

long do_fpu_taskswitch(int set)
{
    struct vcpu *v = current;

    if ( set )
    {
        v->arch.pv_vcpu.ctrlreg[0] |= X86_CR0_TS;
        stts();
    }
    else
    {
        v->arch.pv_vcpu.ctrlreg[0] &= ~X86_CR0_TS;
        if ( v->fpu_dirtied )
            clts();
    }

    return 0;
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

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0 ... 3:
    case 6:
        return curr->arch.debugreg[reg];
    case 7:
        return (curr->arch.debugreg[7] |
                curr->arch.debugreg[5]);
    case 4 ... 5:
        return ((curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_DE) ?
                curr->arch.debugreg[reg + 2] : 0);
    }

    return -EINVAL;
}

void pv_inject_event(const struct x86_event *event)
{
    struct vcpu *v = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct trap_bounce *tb;
    const struct trap_info *ti;
    const uint8_t vector = event->vector;
    const bool use_error_code =
        ((vector < 32) && (TRAP_HAVE_EC & (1u << vector)));
    unsigned int error_code = event->error_code;

    ASSERT(vector == event->vector); /* Confirm no truncation. */
    if ( use_error_code )
        ASSERT(error_code != X86_EVENT_NO_EC);
    else
        ASSERT(error_code == X86_EVENT_NO_EC);

    tb = &v->arch.pv_vcpu.trap_bounce;
    ti = &v->arch.pv_vcpu.trap_ctxt[vector];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( vector == TRAP_page_fault )
    {
        v->arch.pv_vcpu.ctrlreg[2] = event->cr2;
        arch_set_cr2(v, event->cr2);

        /* Re-set error_code.user flag appropriately for the guest. */
        error_code &= ~PFEC_user_mode;
        if ( !guest_kernel_mode(v, regs) )
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

    if ( unlikely(null_trap_bounce(v, tb)) )
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
 * Returns 0 if no callback is set up, else 1.
 */
int set_guest_machinecheck_trapbounce(void)
{
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.pv_vcpu.trap_bounce;

    pv_inject_trap(TRAP_machine_check, guest_cpu_user_regs());
    tb->flags &= ~TBF_EXCEPTION; /* not needed for MCE delivery path */
    return !null_trap_bounce(v, tb);
}

/*
 * Called from asm to set up the NMI trapbounce info.
 * Returns 0 if no callback is set up, else 1.
 */
int set_guest_nmi_trapbounce(void)
{
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.pv_vcpu.trap_bounce;
    pv_inject_trap(TRAP_nmi, guest_cpu_user_regs());
    tb->flags &= ~TBF_EXCEPTION; /* not needed for NMI delivery path */
    return !null_trap_bounce(v, tb);
}

long register_guest_nmi_callback(unsigned long address)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct trap_info *t = &v->arch.pv_vcpu.trap_ctxt[TRAP_nmi];

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
    if ( (v->vcpu_id == 0) && (arch_get_nmi_reason(d) != 0) )
        v->nmi_pending = 1;

    return 0;
}

long unregister_guest_nmi_callback(void)
{
    struct vcpu *v = current;
    struct trap_info *t = &v->arch.pv_vcpu.trap_ctxt[TRAP_nmi];

    memset(t, 0, sizeof(*t));

    return 0;
}

int guest_has_trap_callback(struct domain *d, uint16_t vcpuid,
                            unsigned int trap_nr)
{
    struct vcpu *v;
    struct trap_info *t;

    BUG_ON(d == NULL);
    BUG_ON(vcpuid >= d->max_vcpus);

    /* Sanity check - XXX should be more fine grained. */
    BUG_ON(trap_nr >= NR_VECTORS);

    v = d->vcpu[vcpuid];
    t = &v->arch.pv_vcpu.trap_ctxt[trap_nr];

    return (t->address != 0);
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
