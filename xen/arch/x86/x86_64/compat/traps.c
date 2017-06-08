#include <xen/event.h>
#include <asm/regs.h>
#include <compat/callback.h>
#include <compat/arch-x86_32.h>

void compat_show_guest_stack(struct vcpu *v, const struct cpu_user_regs *regs,
                             int debug_stack_lines)
{
    unsigned int i, *stack, addr, mask = STACK_SIZE;

    stack = (unsigned int *)(unsigned long)regs->esp;
    printk("Guest stack trace from esp=%08lx:\n ", (unsigned long)stack);

    if ( !__compat_access_ok(v->domain, stack, sizeof(*stack)) )
    {
        printk("Guest-inaccessible memory.\n");
        return;
    }

    if ( v != current )
    {
        struct vcpu *vcpu;
        unsigned long mfn;

        ASSERT(guest_kernel_mode(v, regs));
        mfn = read_cr3() >> PAGE_SHIFT;
        for_each_vcpu( v->domain, vcpu )
            if ( pagetable_get_pfn(vcpu->arch.guest_table) == mfn )
                break;
        if ( !vcpu )
        {
            stack = do_page_walk(v, (unsigned long)stack);
            if ( (unsigned long)stack < PAGE_SIZE )
            {
                printk("Inaccessible guest memory.\n");
                return;
            }
            mask = PAGE_SIZE;
        }
    }

    for ( i = 0; i < debug_stack_lines * 8; i++ )
    {
        if ( (((long)stack - 1) ^ ((long)(stack + 1) - 1)) & mask )
            break;
        if ( __get_user(addr, stack) )
        {
            if ( i != 0 )
                printk("\n    ");
            printk("Fault while accessing guest memory.");
            i = 1;
            break;
        }
        if ( (i != 0) && ((i % 8) == 0) )
            printk("\n ");
        printk(" %08x", addr);
        stack++;
    }
    if ( mask == PAGE_SIZE )
    {
        BUILD_BUG_ON(PAGE_SIZE == STACK_SIZE);
        unmap_domain_page(stack);
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

static long compat_register_guest_callback(
    struct compat_callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    fixup_guest_code_selector(v->domain, reg->address.cs);

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.pv_vcpu.event_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.event_callback_eip    = reg->address.eip;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.pv_vcpu.failsafe_callback_cs  = reg->address.cs;
        v->arch.pv_vcpu.failsafe_callback_eip = reg->address.eip;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall32:
        v->arch.pv_vcpu.syscall32_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.syscall32_callback_eip    = reg->address.eip;
        v->arch.pv_vcpu.syscall32_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_sysenter:
        v->arch.pv_vcpu.sysenter_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.sysenter_callback_eip    = reg->address.eip;
        v->arch.pv_vcpu.sysenter_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address.eip);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long compat_unregister_guest_callback(
    struct compat_callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
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


long compat_callback_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct compat_callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = compat_register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct compat_callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = compat_unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

long compat_set_callbacks(unsigned long event_selector,
                          unsigned long event_address,
                          unsigned long failsafe_selector,
                          unsigned long failsafe_address)
{
    struct compat_callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = {
            .cs = event_selector,
            .eip = event_address
        }
    };
    struct compat_callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = {
            .cs = failsafe_selector,
            .eip = failsafe_address
        }
    };

    compat_register_guest_callback(&event);
    compat_register_guest_callback(&failsafe);

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
