/******************************************************************************
 * arch/x86/pv/shim.c
 *
 * Functionaltiy for PV Shim mode
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
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/shutdown.h>
#include <xen/types.h>
#include <xen/consoled.h>
#include <xen/pv_console.h>

#include <asm/apic.h>
#include <asm/dom0_build.h>
#include <asm/guest.h>
#include <asm/pv/mm.h>

#include <compat/grant_table.h>

#ifndef CONFIG_PV_SHIM_EXCLUSIVE
bool pv_shim;
boolean_param("pv-shim", pv_shim);
#endif

/*
 * By default, 1/16th of total HVM container's memory is reserved for xen-shim
 * with minimum amount being 10MB and maximum amount 128MB. Some users may wish
 * to tune this constants for better memory utilization. This can be achieved
 * using the following xen-shim's command line option:
 *
 * shim_mem=[min:<min_amt>,][max:<max_amt>,][<amt>]
 *
 * <min_amt>: The minimum amount of memory that should be allocated for xen-shim
 *            (ignored if greater than max)
 * <max_amt>: The maximum amount of memory that should be allocated for xen-shim
 * <amt>:     The precise amount of memory to allocate for xen-shim
 *            (overrides both min and max)
 */
static uint64_t __initdata shim_nrpages;
static uint64_t __initdata shim_min_nrpages = 10UL << (20 - PAGE_SHIFT);
static uint64_t __initdata shim_max_nrpages = 128UL << (20 - PAGE_SHIFT);

static int __init parse_shim_mem(const char *s)
{
    do {
        if ( !strncmp(s, "min:", 4) )
            shim_min_nrpages = parse_size_and_unit(s+4, &s) >> PAGE_SHIFT;
        else if ( !strncmp(s, "max:", 4) )
            shim_max_nrpages = parse_size_and_unit(s+4, &s) >> PAGE_SHIFT;
        else
            shim_nrpages = parse_size_and_unit(s, &s) >> PAGE_SHIFT;
    } while ( *s++ == ',' );

    return s[-1] ? -EINVAL : 0;
}
custom_param("shim_mem", parse_shim_mem);

uint64_t pv_shim_mem(uint64_t avail)
{
    uint64_t rsvd = min(avail / 16, shim_max_nrpages);

    if ( shim_nrpages )
        return shim_nrpages;

    if ( shim_min_nrpages <= shim_max_nrpages )
        rsvd = max(rsvd, shim_min_nrpages);

    return rsvd;
}

static unsigned int nr_grant_list;
static unsigned long *grant_frames;
static DEFINE_SPINLOCK(grant_lock);

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER| \
                 _PAGE_GUEST_KERNEL)
#define COMPAT_L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)

static void __init replace_va(struct domain *d, l4_pgentry_t *l4start,
                              unsigned long va, unsigned long mfn)
{
    struct page_info *page;
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    pl4e = l4start + l4_table_offset(va);
    pl3e = l4e_to_l3e(*pl4e);
    pl3e += l3_table_offset(va);
    pl2e = l3e_to_l2e(*pl3e);
    pl2e += l2_table_offset(va);
    pl1e = l2e_to_l1e(*pl2e);
    pl1e += l1_table_offset(va);

    page = mfn_to_page(l1e_get_pfn(*pl1e));
    /* Free original page, will be replaced */
    put_page_and_type(page);
    free_domheap_pages(page, 0);

    *pl1e = l1e_from_pfn(mfn, (!is_pv_32bit_domain(d) ? L1_PROT
                                                      : COMPAT_L1_PROT));
}

static void evtchn_reserve(struct domain *d, unsigned int port)
{
    struct evtchn_unmask unmask = {
        .port = port,
    };

    ASSERT(port_is_valid(d, port));
    evtchn_from_port(d, port)->state = ECS_RESERVED;
    BUG_ON(xen_hypercall_event_channel_op(EVTCHNOP_unmask, &unmask));
}

static bool evtchn_handled(struct domain *d, unsigned int port)
{
    ASSERT(port_is_valid(d, port));
    /* The shim manages VIRQs, the rest is forwarded to L0. */
    return evtchn_from_port(d, port)->state == ECS_VIRQ;
}

static void evtchn_assign_vcpu(struct domain *d, unsigned int port,
                               unsigned int vcpu)
{
    ASSERT(port_is_valid(d, port));
    evtchn_from_port(d, port)->notify_vcpu_id = vcpu;
}

void __init pv_shim_setup_dom(struct domain *d, l4_pgentry_t *l4start,
                              unsigned long va_start, unsigned long store_va,
                              unsigned long console_va, unsigned long vphysmap,
                              start_info_t *si)
{
    uint64_t param = 0;
    long rc;

#define SET_AND_MAP_PARAM(p, si, va) ({                                        \
    rc = xen_hypercall_hvm_get_param(p, &param);                               \
    if ( rc )                                                                  \
        panic("Unable to get " #p "\n");                                       \
    (si) = param;                                                              \
    if ( va )                                                                  \
    {                                                                          \
        BUG_ON(unshare_xen_page_with_guest(mfn_to_page(param), dom_io));       \
        share_xen_page_with_guest(mfn_to_page(param), d, XENSHARE_writable);   \
        replace_va(d, l4start, va, param);                                     \
        dom0_update_physmap(d, (va - va_start) >> PAGE_SHIFT, param, vphysmap);\
    }                                                                          \
    else                                                                       \
    {                                                                          \
        BUG_ON(evtchn_allocate_port(d, param));                                \
        evtchn_reserve(d, param);                                              \
    }                                                                          \
})
    SET_AND_MAP_PARAM(HVM_PARAM_STORE_PFN, si->store_mfn, store_va);
    SET_AND_MAP_PARAM(HVM_PARAM_STORE_EVTCHN, si->store_evtchn, 0);
    SET_AND_MAP_PARAM(HVM_PARAM_CONSOLE_EVTCHN, si->console.domU.evtchn, 0);
    if ( !pv_console )
        SET_AND_MAP_PARAM(HVM_PARAM_CONSOLE_PFN, si->console.domU.mfn,
                          console_va);
#undef SET_AND_MAP_PARAM
    else
    {
        /* Allocate a new page for DomU's PV console */
        void *page = alloc_xenheap_pages(0, MEMF_bits(32));
        uint64_t console_mfn;

        ASSERT(page);
        clear_page(page);
        console_mfn = virt_to_mfn(page);
        si->console.domU.mfn = console_mfn;
        share_xen_page_with_guest(mfn_to_page(console_mfn), d,
                                  XENSHARE_writable);
        replace_va(d, l4start, console_va, console_mfn);
        dom0_update_physmap(d, (console_va - va_start) >> PAGE_SHIFT,
                            console_mfn, vphysmap);
        consoled_set_ring_addr(page);
    }

    /*
     * Set the max pages to the current number of pages to prevent the
     * guest from depleting the shim memory pool.
     */
    d->max_pages = d->tot_pages;
}

static void write_start_info(struct domain *d)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    start_info_t *si = map_domain_page(_mfn(is_pv_32bit_domain(d) ? regs->edx
                                                                  : regs->rdx));
    uint64_t param;

    BUG_ON(!si);

    snprintf(si->magic, sizeof(si->magic), "xen-3.0-x86_%s",
             is_pv_32bit_domain(d) ? "32p" : "64");
    si->nr_pages = d->tot_pages;
    si->shared_info = virt_to_maddr(d->shared_info);
    si->flags = (xen_processor_pmbits << 8) & SIF_PM_MASK;
    BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_STORE_PFN, &si->store_mfn));
    BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_STORE_EVTCHN, &param));
    si->store_evtchn = param;
    BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_EVTCHN, &param));
    si->console.domU.evtchn = param;
    if ( !pv_console )
        BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_PFN,
                                           &si->console.domU.mfn));
    else
        si->console.domU.mfn = virt_to_mfn(consoled_get_ring_addr());

    if ( is_pv_32bit_domain(d) )
        xlat_start_info(si, XLAT_start_info_console_domU);

    unmap_domain_page(si);
}

int pv_shim_shutdown(uint8_t reason)
{
    long rc;

    if ( reason == SHUTDOWN_suspend )
    {
        struct domain *d = current->domain;
        struct vcpu *v;
        unsigned int i;
        uint64_t old_store_pfn, old_console_pfn = 0, store_pfn, console_pfn;
        uint64_t store_evtchn, console_evtchn;

        BUG_ON(current->vcpu_id != 0);

        BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_STORE_PFN,
                                           &old_store_pfn));
        if ( !pv_console )
            BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_PFN,
                                               &old_console_pfn));

        /* Pause the other vcpus before starting the migration. */
        for_each_vcpu(d, v)
            if ( v != current )
                vcpu_pause_by_systemcontroller(v);

        rc = xen_hypercall_shutdown(SHUTDOWN_suspend);
        if ( rc )
        {
            for_each_vcpu(d, v)
                if ( v != current )
                    vcpu_unpause_by_systemcontroller(v);

            return rc;
        }

        /* Resume the shim itself first. */
        hypervisor_resume();

        /*
         * ATM there's nothing Xen can do if the console/store pfn changes,
         * because Xen won't have a page_info struct for it.
         */
        BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_STORE_PFN,
                                           &store_pfn));
        BUG_ON(old_store_pfn != store_pfn);
        if ( !pv_console )
        {
            BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_PFN,
                                               &console_pfn));
            BUG_ON(old_console_pfn != console_pfn);
        }

        /* Update domain id. */
        d->domain_id = get_dom0_domid();

        /* Clean the iomem range. */
        BUG_ON(iomem_deny_access(d, 0, ~0UL));

        /* Clean grant frames. */
        xfree(grant_frames);
        grant_frames = NULL;
        nr_grant_list = 0;

        /* Clean event channels. */
        for ( i = 0; i < EVTCHN_2L_NR_CHANNELS; i++ )
        {
            if ( !port_is_valid(d, i) )
                continue;

            if ( evtchn_handled(d, i) )
                evtchn_close(d, i, false);
            else
                evtchn_free(d, evtchn_from_port(d, i));
        }

        /* Reserve store/console event channel. */
        BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_STORE_EVTCHN,
                                           &store_evtchn));
        BUG_ON(evtchn_allocate_port(d, store_evtchn));
        evtchn_reserve(d, store_evtchn);
        BUG_ON(xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_EVTCHN,
                                           &console_evtchn));
        BUG_ON(evtchn_allocate_port(d, console_evtchn));
        evtchn_reserve(d, console_evtchn);

        /* Clean watchdogs. */
        watchdog_domain_destroy(d);
        watchdog_domain_init(d);

        /* Clean the PIRQ EOI page. */
        if ( d->arch.pirq_eoi_map != NULL )
        {
            unmap_domain_page_global(d->arch.pirq_eoi_map);
            put_page_and_type(mfn_to_page(d->arch.pirq_eoi_map_mfn));
            d->arch.pirq_eoi_map = NULL;
            d->arch.pirq_eoi_map_mfn = 0;
            d->arch.auto_unmask = 0;
        }

        /*
         * NB: there's no need to fixup the p2m, since the mfns assigned
         * to the PV guest have not changed at all. Just re-write the
         * start_info fields with the appropriate value.
         */
        write_start_info(d);

        for_each_vcpu(d, v)
        {
            /* Unmap guest vcpu_info pages. */
            unmap_vcpu_info(v);

            /* Reset the periodic timer to the default value. */
            v->periodic_period = MILLISECS(10);
            /* Stop the singleshot timer. */
            stop_timer(&v->singleshot_timer);

            if ( test_bit(_VPF_down, &v->pause_flags) )
                BUG_ON(vcpu_reset(v));

            if ( v != current )
                vcpu_unpause_by_systemcontroller(v);
            else
                vcpu_force_reschedule(v);
        }
    }
    else
        /* Forward to L0. */
        rc = xen_hypercall_shutdown(reason);

    return rc;
}

long pv_shim_event_channel_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d = current->domain;
    long rc;

    switch ( cmd )
    {
#define EVTCHN_FORWARD(cmd, port_field)                                 \
case EVTCHNOP_##cmd: {                                                  \
    struct evtchn_##cmd op;                                             \
                                                                        \
    if ( copy_from_guest(&op, arg, 1) != 0 )                            \
        return -EFAULT;                                                 \
                                                                        \
    rc = xen_hypercall_event_channel_op(EVTCHNOP_##cmd, &op);           \
    if ( rc )                                                           \
        break;                                                          \
                                                                        \
    spin_lock(&d->event_lock);                                          \
    rc = evtchn_allocate_port(d, op.port_field);                        \
    if ( rc )                                                           \
    {                                                                   \
        struct evtchn_close close = {                                   \
            .port = op.port_field,                                      \
        };                                                              \
                                                                        \
        BUG_ON(xen_hypercall_event_channel_op(EVTCHNOP_close, &close)); \
    }                                                                   \
    else                                                                \
        evtchn_reserve(d, op.port_field);                               \
    spin_unlock(&d->event_lock);                                        \
                                                                        \
    if ( !rc && __copy_to_guest(arg, &op, 1) )                          \
        rc = -EFAULT;                                                   \
                                                                        \
    break;                                                              \
    }
    EVTCHN_FORWARD(alloc_unbound, port)
    EVTCHN_FORWARD(bind_interdomain, local_port)
#undef EVTCHN_FORWARD

    case EVTCHNOP_bind_virq: {
        struct evtchn_bind_virq virq;
        struct evtchn_alloc_unbound alloc = {
            .dom = DOMID_SELF,
            .remote_dom = DOMID_SELF,
        };

        if ( copy_from_guest(&virq, arg, 1) != 0 )
            return -EFAULT;
        /*
         * The event channel space is actually controlled by L0 Xen, so
         * allocate a port from L0 and then force the VIRQ to be bound to that
         * specific port.
         *
         * This is only required for VIRQ because the rest of the event channel
         * operations are handled directly by L0.
         */
        rc = xen_hypercall_event_channel_op(EVTCHNOP_alloc_unbound, &alloc);
        if ( rc )
           break;

        /* Force L1 to use the event channel port allocated on L0. */
        rc = evtchn_bind_virq(&virq, alloc.port);
        if ( rc )
        {
             struct evtchn_close free = {
                .port = alloc.port,
             };

              xen_hypercall_event_channel_op(EVTCHNOP_close, &free);
        }

        if ( !rc && __copy_to_guest(arg, &virq, 1) )
            rc = -EFAULT;

        break;
    }
    case EVTCHNOP_status: {
        struct evtchn_status status;

        if ( copy_from_guest(&status, arg, 1) != 0 )
            return -EFAULT;

        if ( port_is_valid(d, status.port) && evtchn_handled(d, status.port) )
            rc = evtchn_status(&status);
        else
            rc = xen_hypercall_event_channel_op(EVTCHNOP_status, &status);

        break;
    }
    case EVTCHNOP_bind_vcpu: {
        struct evtchn_bind_vcpu vcpu;

        if ( copy_from_guest(&vcpu, arg, 1) != 0 )
            return -EFAULT;

        if ( !port_is_valid(d, vcpu.port) )
            return -EINVAL;

        if ( evtchn_handled(d, vcpu.port) )
            rc = evtchn_bind_vcpu(vcpu.port, vcpu.vcpu);
        else
        {
            rc = xen_hypercall_event_channel_op(EVTCHNOP_bind_vcpu, &vcpu);
            if ( !rc )
                 evtchn_assign_vcpu(d, vcpu.port, vcpu.vcpu);
        }

        break;
    }
    case EVTCHNOP_close: {
        struct evtchn_close close;

        if ( copy_from_guest(&close, arg, 1) != 0 )
            return -EFAULT;

        if ( !port_is_valid(d, close.port) )
            return -EINVAL;

        if ( evtchn_handled(d, close.port) )
        {
            rc = evtchn_close(d, close.port, true);
            if ( rc )
                break;
        }
        else
            evtchn_free(d, evtchn_from_port(d, close.port));

        rc = xen_hypercall_event_channel_op(EVTCHNOP_close, &close);
        if ( rc )
            /*
             * If the port cannot be closed on the L0 mark it as reserved
             * in the shim to avoid re-using it.
             */
            evtchn_reserve(d, close.port);

        set_bit(close.port, XEN_shared_info->evtchn_mask);

        break;
    }
    case EVTCHNOP_bind_ipi: {
        struct evtchn_bind_ipi ipi;

        if ( copy_from_guest(&ipi, arg, 1) != 0 )
            return -EFAULT;

        rc = xen_hypercall_event_channel_op(EVTCHNOP_bind_ipi, &ipi);
        if ( rc )
            break;

        spin_lock(&d->event_lock);
        rc = evtchn_allocate_port(d, ipi.port);
        if ( rc )
        {
            struct evtchn_close close = {
                .port = ipi.port,
            };

            /*
             * If closing the event channel port also fails there's not
             * much the shim can do, since it has been unable to reserve
             * the port in it's event channel space.
             */
            BUG_ON(xen_hypercall_event_channel_op(EVTCHNOP_close, &close));
            break;
        }

        evtchn_assign_vcpu(d, ipi.port, ipi.vcpu);
        evtchn_reserve(d, ipi.port);
        spin_unlock(&d->event_lock);

        if ( __copy_to_guest(arg, &ipi, 1) )
            rc = -EFAULT;

        break;
    }
    case EVTCHNOP_unmask: {
        struct evtchn_unmask unmask;

        if ( copy_from_guest(&unmask, arg, 1) != 0 )
            return -EFAULT;

        /* Unmask is handled in L1 */
        rc = evtchn_unmask(unmask.port);

        break;
    }
    case EVTCHNOP_send: {
        struct evtchn_send send;

        if ( copy_from_guest(&send, arg, 1) != 0 )
            return -EFAULT;

        if ( pv_console && send.port == pv_console_evtchn() )
        {
            consoled_guest_rx();
            rc = 0;
        }
        else
            rc = xen_hypercall_event_channel_op(EVTCHNOP_send, &send);

        break;
    }
    case EVTCHNOP_reset: {
        struct evtchn_reset reset;

        if ( copy_from_guest(&reset, arg, 1) != 0 )
            return -EFAULT;

        rc = xen_hypercall_event_channel_op(EVTCHNOP_reset, &reset);

        break;
    }
    default:
        /* No FIFO or PIRQ support for now */
        rc = -ENOSYS;
        break;
    }

    return rc;
}

void pv_shim_inject_evtchn(unsigned int port)
{
    if ( port_is_valid(pv_domain, port) )
    {
         struct evtchn *chn = evtchn_from_port(pv_domain, port);

         evtchn_port_set_pending(pv_domain, chn->notify_vcpu_id, chn);
    }
}

long pv_shim_grant_table_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop,
                            unsigned int count, bool compat)
{
    struct domain *d = current->domain;
    long rc = 0;

    if ( count != 1 )
        return -EINVAL;

    switch ( cmd )
    {
    case GNTTABOP_setup_table:
    {
        struct gnttab_setup_table nat;
        struct compat_gnttab_setup_table cmp;
        unsigned int i;

        if ( unlikely(compat ? copy_from_guest(&cmp, uop, 1)
                             : copy_from_guest(&nat, uop, 1)) ||
             unlikely(compat ? !compat_handle_okay(cmp.frame_list,
                                                   cmp.nr_frames)
                             : !guest_handle_okay(nat.frame_list,
                                                  nat.nr_frames)) )
        {
            rc = -EFAULT;
            break;
        }
        if ( compat )
#define XLAT_gnttab_setup_table_HNDL_frame_list(d, s)
                XLAT_gnttab_setup_table(&nat, &cmp);
#undef XLAT_gnttab_setup_table_HNDL_frame_list

        nat.status = GNTST_okay;

        spin_lock(&grant_lock);
        if ( !nr_grant_list )
        {
            struct gnttab_query_size query_size = {
                .dom = DOMID_SELF,
            };

            rc = xen_hypercall_grant_table_op(GNTTABOP_query_size,
                                              &query_size, 1);
            if ( rc )
            {
                spin_unlock(&grant_lock);
                break;
            }

            ASSERT(!grant_frames);
            grant_frames = xzalloc_array(unsigned long,
                                         query_size.max_nr_frames);
            if ( !grant_frames )
            {
                spin_unlock(&grant_lock);
                rc = -ENOMEM;
                break;
            }

            nr_grant_list = query_size.max_nr_frames;
        }

        if ( nat.nr_frames > nr_grant_list )
        {
            spin_unlock(&grant_lock);
            rc = -EINVAL;
            break;
        }

        for ( i = 0; i < nat.nr_frames; i++ )
        {
            if ( !grant_frames[i] )
            {
                struct xen_add_to_physmap xatp = {
                    .domid = DOMID_SELF,
                    .idx = i,
                    .space = XENMAPSPACE_grant_table,
                };
                mfn_t mfn;

                rc = hypervisor_alloc_unused_page(&mfn);
                if ( rc )
                {
                    gprintk(XENLOG_ERR,
                            "unable to get memory for grant table\n");
                    break;
                }

                xatp.gpfn = mfn_x(mfn);
                rc = xen_hypercall_memory_op(XENMEM_add_to_physmap, &xatp);
                if ( rc )
                {
                    hypervisor_free_unused_page(mfn);
                    break;
                }

                BUG_ON(iomem_permit_access(d, mfn_x(mfn), mfn_x(mfn)));
                grant_frames[i] = mfn_x(mfn);
            }

            ASSERT(grant_frames[i]);
            if ( compat )
            {
                compat_pfn_t pfn = grant_frames[i];

                if ( __copy_to_compat_offset(cmp.frame_list, i, &pfn, 1) )
                {
                    nat.status = GNTST_bad_virt_addr;
                    rc = -EFAULT;
                    break;
                }
            }
            else if ( __copy_to_guest_offset(nat.frame_list, i,
                                             &grant_frames[i], 1) )
            {
                nat.status = GNTST_bad_virt_addr;
                rc = -EFAULT;
                break;
            }
        }
        spin_unlock(&grant_lock);

        if ( compat )
#define XLAT_gnttab_setup_table_HNDL_frame_list(d, s)
                XLAT_gnttab_setup_table(&cmp, &nat);
#undef XLAT_gnttab_setup_table_HNDL_frame_list

        if ( unlikely(compat ? copy_to_guest(uop, &cmp, 1)
                             : copy_to_guest(uop, &nat, 1)) )
        {
            rc = -EFAULT;
            break;
        }

        break;
    }
    case GNTTABOP_query_size:
    {
        struct gnttab_query_size op;
        int rc;

        if ( unlikely(copy_from_guest(&op, uop, 1)) )
        {
            rc = -EFAULT;
            break;
        }

        rc = xen_hypercall_grant_table_op(GNTTABOP_query_size, &op, count);
        if ( rc )
            break;

        if ( copy_to_guest(uop, &op, 1) )
        {
            rc = -EFAULT;
            break;
        }

        break;
    }
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

long pv_shim_cpu_up(void *data)
{
    struct vcpu *v = data;
    long rc;

    BUG_ON(smp_processor_id() != 0);

    if ( !cpu_online(v->vcpu_id) )
    {
        rc = cpu_up_helper((void *)(unsigned long)v->vcpu_id);
        if ( rc )
        {
            gprintk(XENLOG_ERR, "Failed to bring up CPU#%u: %ld\n",
                    v->vcpu_id, rc);
            return rc;
        }
    }

    return vcpu_up(v);
}

long pv_shim_cpu_down(void *data)
{
    struct vcpu *v = data;
    long rc;

    BUG_ON(smp_processor_id() != 0);

    if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
        vcpu_sleep_sync(v);

    if ( cpu_online(v->vcpu_id) )
    {
        rc = cpu_down_helper((void *)(unsigned long)v->vcpu_id);
        if ( rc )
            gprintk(XENLOG_ERR, "Failed to bring down CPU#%u: %ld\n",
                    v->vcpu_id, rc);
        /*
         * NB: do not propagate errors from cpu_down_helper failing. The shim
         * is going to run with extra CPUs, but that's not going to prevent
         * normal operation. OTOH most guests are not prepared to handle an
         * error on VCPUOP_down failing, and will likely panic.
         */
    }

    return 0;
}

domid_t get_dom0_domid(void)
{
    uint32_t eax, ebx, ecx, edx;

    if ( !pv_shim )
        return 0;

    cpuid(hypervisor_cpuid_base() + 1, &eax, &ebx, &ecx, &edx);

    return ebx ?: 1;
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
