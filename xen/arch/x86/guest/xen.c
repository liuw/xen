/******************************************************************************
 * arch/x86/guest/xen.c
 *
 * Support for detecting and running under Xen.
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
#include <xen/init.h>
#include <xen/types.h>

#include <asm/apic.h>
#include <asm/guest.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include <public/arch-x86/cpuid.h>

bool xen_guest;

static uint32_t xen_cpuid_base;
static uint8_t evtchn_upcall_vector;
extern char hypercall_page[];

static void __init find_xen_leaves(void)
{
    uint32_t eax, ebx, ecx, edx, base;

    for ( base = XEN_CPUID_FIRST_LEAF;
          base < XEN_CPUID_FIRST_LEAF + 0x10000; base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx);

        if ( (ebx == XEN_CPUID_SIGNATURE_EBX) &&
             (ecx == XEN_CPUID_SIGNATURE_ECX) &&
             (edx == XEN_CPUID_SIGNATURE_EDX) &&
             ((eax - base) >= 2) )
        {
            xen_cpuid_base = base;
            break;
        }
    }
}

void __init probe_hypervisor(void)
{
    if ( xen_guest )
        return;

    /* Too early to use cpu_has_hypervisor */
    if ( !(cpuid_ecx(1) & cpufeat_mask(X86_FEATURE_HYPERVISOR)) )
        return;

    find_xen_leaves();

    if ( !xen_cpuid_base )
        return;

    /* Fill the hypercall page. */
    wrmsrl(cpuid_ebx(xen_cpuid_base + 2), __pa(hypercall_page));

    xen_guest = true;
}

static void map_shared_info(struct e820map *e820)
{
    paddr_t frame = 0xff000000; /* TODO: Hardcoded beside magic frames. */
    struct xen_add_to_physmap xatp = {
        .domid = DOMID_SELF,
        .idx = 0,
        .space = XENMAPSPACE_shared_info,
        .gpfn = frame >> PAGE_SHIFT,
    };

    if ( !e820_add_range(e820, frame, frame + PAGE_SIZE, E820_RESERVED) )
        panic("Failed to reserve shared_info range");

    if ( xen_hypercall_memory_op(XENMEM_add_to_physmap, &xatp) )
        panic("Failed to map shared_info page");

    set_fixmap(FIX_XEN_SHARED_INFO, frame);
}

static void xen_evtchn_upcall(struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();
    struct vcpu_info *vcpu_info = &XEN_shared_info->vcpu_info[cpu];

    vcpu_info->evtchn_upcall_pending = 0;
    xchg(&vcpu_info->evtchn_pending_sel, 0);

    ack_APIC_irq();
}

static void ap_setup_event_channels(bool clear)
{
    unsigned int i, cpu = smp_processor_id();
    struct vcpu_info *vcpu_info = &XEN_shared_info->vcpu_info[cpu];
    int rc;

    ASSERT(evtchn_upcall_vector);
    ASSERT(cpu < ARRAY_SIZE(XEN_shared_info->vcpu_info));

    if ( !clear )
    {
        /*
         * This is necessary to ensure that a CPU will be interrupted in case
         * of an event channel notification.
         */
        ASSERT(vcpu_info->evtchn_upcall_pending == 0);
        ASSERT(vcpu_info->evtchn_pending_sel == 0);
    }

    rc = xen_hypercall_set_evtchn_upcall_vector(cpu, evtchn_upcall_vector);
    if ( rc )
        panic("Unable to set evtchn upcall vector: %d", rc);

    if ( clear )
    {
        /*
         * Clear any pending upcall bits. This makes us effectively ignore any
         * previous upcalls which might be suboptimal.
         */
        vcpu_info->evtchn_upcall_pending = 0;
        xchg(&vcpu_info->evtchn_pending_sel, 0);

        /*
         * evtchn_pending can be cleared only on the boot CPU because it's
         * located in a shared structure.
         */
        for ( i = 0; i < 8; i++ )
            xchg(&XEN_shared_info->evtchn_pending[i], 0);
    }
}

static void __init init_evtchn(void)
{
    unsigned int i;

    alloc_direct_apic_vector(&evtchn_upcall_vector, xen_evtchn_upcall);

    /* Mask all upcalls */
    for ( i = 0; i < 8; i++ )
        xchg(&XEN_shared_info->evtchn_mask[i], ~0ul);

    ap_setup_event_channels(true);
}

void __init hypervisor_early_setup(struct e820map *e820)
{
    map_shared_info(e820);

    init_evtchn();
}

void hypervisor_ap_setup(void)
{
    ap_setup_event_channels(false);
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
