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
#include <asm/debugreg.h>
#include <asm/shared.h>
#include <asm/traps.h>

#include <public/callback.h>

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

    tb = &v->arch.pv_vcpu.trap_bounce;
    ti = &v->arch.pv_vcpu.trap_ctxt[vector];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION &&
         vector == TRAP_page_fault )
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

    pv_inject_hw_exception(TRAP_machine_check, X86_EVENT_NO_EC);
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
    pv_inject_hw_exception(TRAP_nmi, X86_EVENT_NO_EC);
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

int send_guest_trap(struct domain *d, uint16_t vcpuid, unsigned int trap_nr)
{
    struct vcpu *v;
    struct softirq_trap *st = &per_cpu(softirq_trap, smp_processor_id());

    BUG_ON(d == NULL);
    BUG_ON(vcpuid >= d->max_vcpus);
    v = d->vcpu[vcpuid];

    switch (trap_nr)
    {
    case TRAP_nmi:
        if ( cmpxchgptr(&st->vcpu, NULL, v) )
            return -EBUSY;
        if ( !test_and_set_bool(v->nmi_pending) )
        {
               st->domain = d;
               st->processor = v->processor;

               /* not safe to wake up a vcpu here */
               raise_softirq(NMI_MCE_SOFTIRQ);
               return 0;
        }
        st->vcpu = NULL;
        break;

    case TRAP_machine_check:
        if ( cmpxchgptr(&st->vcpu, NULL, v) )
            return -EBUSY;

        /* We are called by the machine check (exception or polling) handlers
         * on the physical CPU that reported a machine check error. */

        if ( !test_and_set_bool(v->mce_pending) )
        {
                st->domain = d;
                st->processor = v->processor;

                /* not safe to wake up a vcpu here */
                raise_softirq(NMI_MCE_SOFTIRQ);
                return 0;
        }
        st->vcpu = NULL;
        break;
    }

    /* delivery failed */
    return -EIO;
}

void toggle_guest_mode(struct vcpu *v)
{
    if ( is_pv_32bit_vcpu(v) )
        return;
    if ( cpu_has_fsgsbase )
    {
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv_vcpu.gs_base_kernel = __rdgsbase();
        else
            v->arch.pv_vcpu.gs_base_user = __rdgsbase();
    }
    v->arch.flags ^= TF_kernel_mode;
    asm volatile ( "swapgs" );
    update_cr3(v);
    /* Don't flush user global mappings from the TLB. Don't tick TLB clock. */
    asm volatile ( "mov %0, %%cr3" : : "r" (v->arch.cr3) : "memory" );

    if ( !(v->arch.flags & TF_kernel_mode) )
        return;

    if ( v->arch.pv_vcpu.need_update_runstate_area &&
         update_runstate_area(v) )
        v->arch.pv_vcpu.need_update_runstate_area = 0;

    if ( v->arch.pv_vcpu.pending_system_time.version &&
         update_secondary_system_time(v,
                                      &v->arch.pv_vcpu.pending_system_time) )
        v->arch.pv_vcpu.pending_system_time.version = 0;
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp,
                                 sizeof(iret_saved))) )
    {
        gprintk(XENLOG_ERR,
                "Fault while reading IRET context from guest stack\n");
        goto exit_and_crash;
    }

    /* Returning to user mode? */
    if ( (iret_saved.cs & 3) == 3 )
    {
        if ( unlikely(pagetable_is_null(v->arch.guest_table_user)) )
        {
            gprintk(XENLOG_ERR,
                    "Guest switching to user mode with no user page tables\n");
            goto exit_and_crash;
        }
        toggle_guest_mode(v);
    }

    if ( VM_ASSIST(v->domain, architectural_iopl) )
        v->arch.pv_vcpu.iopl = iret_saved.rflags & X86_EFLAGS_IOPL;

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = ((iret_saved.rflags & ~(X86_EFLAGS_IOPL|X86_EFLAGS_VM))
                    | X86_EFLAGS_IF);
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_in_syscall) )
    {
        regs->entry_vector &= ~TRAP_syscall;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(iret_saved.rflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
}

void init_int80_direct_trap(struct vcpu *v)
{
    struct trap_info *ti = &v->arch.pv_vcpu.trap_ctxt[0x80];
    struct trap_bounce *tb = &v->arch.pv_vcpu.int80_bounce;

    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( null_trap_bounce(v, tb) )
        tb->flags = 0;
    else
        tb->flags = TBF_EXCEPTION | (TI_GET_IF(ti) ? TBF_INTERRUPT : 0);
}

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    if ( !is_canonical_address(reg->address) )
        return -EINVAL;

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.pv_vcpu.event_callback_eip    = reg->address;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.pv_vcpu.failsafe_callback_eip = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall:
        v->arch.pv_vcpu.syscall_callback_eip  = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_syscall_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_syscall_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall32:
        v->arch.pv_vcpu.syscall32_callback_eip = reg->address;
        v->arch.pv_vcpu.syscall32_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_sysenter:
        v->arch.pv_vcpu.sysenter_callback_eip = reg->address;
        v->arch.pv_vcpu.sysenter_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long unregister_guest_callback(struct callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
    case CALLBACKTYPE_syscall:
    case CALLBACKTYPE_syscall32:
    case CALLBACKTYPE_sysenter:
        ret = -EINVAL;
        break;

    case CALLBACKTYPE_nmi:
        ret = unregister_guest_nmi_callback();
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long do_callback_op(int cmd, XEN_GUEST_HANDLE_PARAM(const_void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = event_address,
    };
    struct callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = failsafe_address,
    };
    struct callback_register syscall = {
        .type = CALLBACKTYPE_syscall,
        .address = syscall_address,
    };

    register_guest_callback(&event);
    register_guest_callback(&failsafe);
    register_guest_callback(&syscall);

    return 0;
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
