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
#include <xen/event.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/pv_console.h>
#include <xen/rangeset.h>

#include <asm/apic.h>
#include <asm/guest.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include <public/arch-x86/cpuid.h>
#include <public/hvm/params.h>

bool xen_guest;

static uint32_t xen_cpuid_base;
extern char hypercall_page[];
static struct rangeset *mem;

DEFINE_PER_CPU(unsigned int, vcpu_id);

static struct vcpu_info *vcpu_info;
unsigned long vcpu_info_mapped[BITS_TO_LONGS(NR_CPUS)];
DEFINE_PER_CPU(struct vcpu_info *, vcpu_info);

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

static void map_shared_info(void)
{
    mfn_t mfn;
    struct xen_add_to_physmap xatp = {
        .domid = DOMID_SELF,
        .space = XENMAPSPACE_shared_info,
    };
    unsigned int i;

    if ( hypervisor_alloc_unused_page(&mfn) )
        panic("unable to reserve shared info memory page");

    xatp.gpfn = mfn_x(mfn);
    if ( xen_hypercall_memory_op(XENMEM_add_to_physmap, &xatp) )
        panic("Failed to map shared_info page");

    set_fixmap(FIX_XEN_SHARED_INFO, mfn_x(mfn) << PAGE_SHIFT);

    /* Mask all upcalls */
    for ( i = 0; i < ARRAY_SIZE(XEN_shared_info->evtchn_mask); i++ )
        xchg(&XEN_shared_info->evtchn_mask[i], ~0ul);
}

static int map_vcpuinfo(void)
{
    unsigned int vcpu = this_cpu(vcpu_id);
    struct vcpu_register_vcpu_info info = { };
    long rc;

    if ( !vcpu_info )
    {
        this_cpu(vcpu_info) = &XEN_shared_info->vcpu_info[vcpu];
        return 0;
    }

    if ( test_bit(vcpu, vcpu_info_mapped) )
    {
        this_cpu(vcpu_info) = &vcpu_info[vcpu];
        return 0;
    }

    info.mfn = virt_to_mfn(&vcpu_info[vcpu]);
    info.offset = (unsigned long)&vcpu_info[vcpu] & ~PAGE_MASK;
    rc = xen_hypercall_vcpu_op(VCPUOP_register_vcpu_info, vcpu, &info);
    if ( rc )
        this_cpu(vcpu_info) = &XEN_shared_info->vcpu_info[vcpu];
    else
    {
        this_cpu(vcpu_info) = &vcpu_info[vcpu];
        set_bit(vcpu, vcpu_info_mapped);
    }

    return rc;
}

static void set_vcpu_id(void)
{
    uint32_t eax, ebx, ecx, edx;

    ASSERT(xen_cpuid_base);

    /* Fetch vcpu id from cpuid. */
    cpuid(xen_cpuid_base + 4, &eax, &ebx, &ecx, &edx);
    if ( eax & XEN_HVM_CPUID_VCPU_ID_PRESENT )
        this_cpu(vcpu_id) = ebx;
    else
        this_cpu(vcpu_id) = smp_processor_id();
}

static void xen_evtchn_upcall(struct cpu_user_regs *regs)
{
    struct vcpu_info *vcpu_info = this_cpu(vcpu_info);
    unsigned long pending;

    vcpu_info->evtchn_upcall_pending = 0;
    pending = xchg(&vcpu_info->evtchn_pending_sel, 0);

    while ( pending )
    {
        unsigned int l1 = ffsl(pending) - 1;
        unsigned long evtchn = xchg(&XEN_shared_info->evtchn_pending[l1], 0);

        __clear_bit(l1, &pending);
        evtchn &= ~XEN_shared_info->evtchn_mask[l1];
        while ( evtchn )
        {
            unsigned int port = ffsl(evtchn) - 1;

            __clear_bit(port, &evtchn);
            port += l1 * BITS_PER_LONG;

            if ( pv_console && port == pv_console_evtchn() )
                pv_console_rx(regs);
            else if ( pv_shim )
                pv_shim_inject_evtchn(port);
        }
    }

    ack_APIC_irq();
}

static void init_evtchn(void)
{
    unsigned int vcpu = this_cpu(vcpu_id);
    static uint8_t evtchn_upcall_vector;
    int rc;

    if ( !evtchn_upcall_vector )
        alloc_direct_apic_vector(&evtchn_upcall_vector, xen_evtchn_upcall);

    ASSERT(evtchn_upcall_vector);
    ASSERT(vcpu < ARRAY_SIZE(XEN_shared_info->vcpu_info));

    rc = xen_hypercall_set_evtchn_upcall_vector(vcpu, evtchn_upcall_vector);
    if ( rc )
        panic("Unable to set evtchn upcall vector: %d", rc);
}

static void __init init_memmap(void)
{
    unsigned int i;

    mem = rangeset_new(NULL, "host memory map", 0);
    if ( !mem )
        panic("failed to allocate host memory rangeset");

    /* Mark up to the last memory page (or 4GB) as RAM. */
    if ( rangeset_add_range(mem, 0, max_t(unsigned long, max_page,
                                          (GB(4) - 1) >> PAGE_SHIFT)) )
        panic("unable to add RAM to memory rangeset");

    for ( i = 0; i < e820.nr_map; i++ )
    {
        struct e820entry *e = &e820.map[i];

        if ( rangeset_add_range(mem, e->addr >> PAGE_SHIFT,
                                (e->addr + e->size) >> PAGE_SHIFT) )
            panic("unable to add range %#lx - %#lx to memory rangeset",
                  e->addr, e->addr + e->size);
    }
}

void __init hypervisor_setup(void)
{
    init_memmap();

    map_shared_info();
    set_vcpu_id();

    vcpu_info = xzalloc_array(struct vcpu_info, nr_cpu_ids);
    if ( map_vcpuinfo() || !vcpu_info )
    {
        if ( vcpu_info )
        {
            xfree(vcpu_info);
            vcpu_info = NULL;
        }
        if ( nr_cpu_ids > XEN_LEGACY_MAX_VCPUS )
        {
            unsigned int i;

            for ( i = XEN_LEGACY_MAX_VCPUS; i < nr_cpu_ids; i++ )
                __cpumask_clear_cpu(i, &cpu_present_map);
            nr_cpu_ids = XEN_LEGACY_MAX_VCPUS;
            printk(XENLOG_WARNING
                   "unable to map vCPU info, limiting vCPUs to: %u\n",
                   XEN_LEGACY_MAX_VCPUS);
        }
    }

    init_evtchn();
}

void hypervisor_ap_setup(void)
{
    set_vcpu_id();
    map_vcpuinfo();
    init_evtchn();
}

int hypervisor_alloc_unused_page(mfn_t *mfn)
{
    unsigned long m;
    int rc;

    rc = rangeset_reserve_hole(mem, 1, &m);
    if ( !rc )
        *mfn = _mfn(m);

    return rc;
}

int hypervisor_free_unused_page(mfn_t mfn)
{
    return rangeset_remove_range(mem, mfn_x(mfn), mfn_x(mfn));
}

static void __init mark_pfn_as_ram(struct e820map *e820, uint64_t pfn)
{
    if ( !e820_add_range(e820, pfn << PAGE_SHIFT,
                         (pfn << PAGE_SHIFT) + PAGE_SIZE, E820_RAM) )
        if ( !e820_change_range_type(e820, pfn << PAGE_SHIFT,
                                     (pfn << PAGE_SHIFT) + PAGE_SIZE,
                                     E820_RESERVED, E820_RAM) )
            panic("Unable to add/change memory type of pfn %#lx to RAM", pfn);
}

void __init hypervisor_fixup_e820(struct e820map *e820)
{
    uint64_t pfn = 0;
    long rc;

    if ( !xen_guest )
        return;

#define MARK_PARAM_RAM(p) ({                    \
    rc = xen_hypercall_hvm_get_param(p, &pfn);  \
    if ( rc )                                   \
        panic("Unable to get " #p);             \
    mark_pfn_as_ram(e820, pfn);                 \
})
    MARK_PARAM_RAM(HVM_PARAM_STORE_PFN);
    if ( !pv_console )
        MARK_PARAM_RAM(HVM_PARAM_CONSOLE_PFN);
#undef MARK_PARAM_RAM
}

void __init hypervisor_init_memory(void)
{
    uint64_t pfn = 0;
    long rc;

    if ( !xen_guest )
        return;

#define SHARE_PARAM(p) ({                                                   \
    rc = xen_hypercall_hvm_get_param(p, &pfn);                              \
    if ( rc )                                                               \
        panic("Unable to get " #p);                                         \
    share_xen_page_with_guest(mfn_to_page(pfn), dom_io, XENSHARE_writable); \
})
    SHARE_PARAM(HVM_PARAM_STORE_PFN);
    if ( !pv_console )
        SHARE_PARAM(HVM_PARAM_CONSOLE_PFN);
#undef SHARE_PARAM
}

const unsigned long *__init hypervisor_reserved_pages(unsigned int *size)
{
    static unsigned long __initdata reserved_pages[2];
    uint64_t pfn = 0;
    long rc;

    if ( !xen_guest )
        return NULL;

    *size = 0;

#define RESERVE_PARAM(p) ({                             \
    rc = xen_hypercall_hvm_get_param(p, &pfn);          \
    if ( rc )                                           \
        panic("Unable to get " #p);                     \
    reserved_pages[(*size)++] = pfn << PAGE_SHIFT;      \
})
    RESERVE_PARAM(HVM_PARAM_STORE_PFN);
    if ( !pv_console )
        RESERVE_PARAM(HVM_PARAM_CONSOLE_PFN);
#undef RESERVE_PARAM

    return reserved_pages;
}

uint32_t hypervisor_cpuid_base(void)
{
    return xen_cpuid_base;
}

void ap_resume(void *unused)
{
    map_vcpuinfo();
    init_evtchn();
}

void hypervisor_resume(void)
{
    /* Reset shared info page. */
    map_shared_info();

    /*
     * Reset vcpu_info. Just clean the mapped bitmap and try to map the vcpu
     * area again. On failure to map (when it was previously mapped) panic
     * since it's impossible to safely shut down running guest vCPUs in order
     * to meet the new XEN_LEGACY_MAX_VCPUS requirement.
     */
    memset(vcpu_info_mapped, 0, sizeof(vcpu_info_mapped));
    if ( map_vcpuinfo() && nr_cpu_ids > XEN_LEGACY_MAX_VCPUS )
        panic("unable to remap vCPU info and vCPUs > legacy limit");

    /* Setup event channel upcall vector. */
    init_evtchn();
    smp_call_function(ap_resume, NULL, 1);

    if ( pv_console )
        pv_console_init();
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
