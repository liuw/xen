/******************************************************************************
 * arch/x86/pv/mm-hypercalls.c
 *
 * Memory management hypercalls for PV guests
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
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
 */

#include <xen/event.h>
#include <xen/guest_access.h>

#include <asm/hypercall.h>
#include <asm/iocap.h>
#include <asm/ldt.h>
#include <asm/mm.h>
#include <asm/p2m.h>
#include <asm/pv/mm.h>
#include <asm/setup.h>

#include <xsm/xsm.h>

#include "mm.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

static struct domain *get_pg_owner(domid_t domid)
{
    struct domain *pg_owner = NULL, *curr = current->domain;

    if ( likely(domid == DOMID_SELF) )
    {
        pg_owner = rcu_lock_current_domain();
        goto out;
    }

    if ( unlikely(domid == curr->domain_id) )
    {
        gdprintk(XENLOG_WARNING, "Cannot specify itself as foreign domain\n");
        goto out;
    }

    switch ( domid )
    {
    case DOMID_IO:
        pg_owner = rcu_lock_domain(dom_io);
        break;
    case DOMID_XEN:
        pg_owner = rcu_lock_domain(dom_xen);
        break;
    default:
        if ( (pg_owner = rcu_lock_domain_by_id(domid)) == NULL )
        {
            gdprintk(XENLOG_WARNING, "Unknown domain d%d\n", domid);
            break;
        }
        break;
    }

 out:
    return pg_owner;
}

static void put_pg_owner(struct domain *pg_owner)
{
    rcu_unlock_domain(pg_owner);
}

static inline int vcpumask_to_pcpumask(
    struct domain *d, XEN_GUEST_HANDLE_PARAM(const_void) bmap, cpumask_t *pmask)
{
    unsigned int vcpu_id, vcpu_bias, offs;
    unsigned long vmask;
    struct vcpu *v;
    bool is_native = !is_pv_32bit_domain(d);

    cpumask_clear(pmask);
    for ( vmask = 0, offs = 0; ; ++offs )
    {
        vcpu_bias = offs * (is_native ? BITS_PER_LONG : 32);
        if ( vcpu_bias >= d->max_vcpus )
            return 0;

        if ( unlikely(is_native ?
                      copy_from_guest_offset(&vmask, bmap, offs, 1) :
                      copy_from_guest_offset((unsigned int *)&vmask, bmap,
                                             offs, 1)) )
        {
            cpumask_clear(pmask);
            return -EFAULT;
        }

        while ( vmask )
        {
            vcpu_id = find_first_set_bit(vmask);
            vmask &= ~(1UL << vcpu_id);
            vcpu_id += vcpu_bias;
            if ( (vcpu_id >= d->max_vcpus) )
                return 0;
            if ( ((v = d->vcpu[vcpu_id]) != NULL) )
                cpumask_or(pmask, pmask, v->vcpu_dirty_cpumask);
        }
    }
}

/*
 * PTE flags that a guest may change without re-validating the PTE.
 * All other bits affect translation, caching, or Xen's safety.
 */
#define FASTPATH_FLAG_WHITELIST                                     \
    (_PAGE_NX_BIT | _PAGE_AVAIL_HIGH | _PAGE_AVAIL | _PAGE_GLOBAL | \
     _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_USER)

/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e,
                        unsigned long gl1mfn, int preserve_ad,
                        struct vcpu *pt_vcpu, struct domain *pg_dom)
{
    l1_pgentry_t ol1e;
    struct domain *pt_dom = pt_vcpu->domain;
    int rc = 0;

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) )
        return -EFAULT;

    ASSERT(!paging_mode_refcounts(pt_dom));

    if ( l1e_get_flags(nl1e) & _PAGE_PRESENT )
    {
        /* Translate foreign guest addresses. */
        struct page_info *page = NULL;

        if ( unlikely(l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom)) )
        {
            gdprintk(XENLOG_WARNING, "Bad L1 flags %x\n",
                    l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom));
            return -EINVAL;
        }

        if ( paging_mode_translate(pg_dom) )
        {
            page = get_page_from_gfn(pg_dom, l1e_get_pfn(nl1e), NULL, P2M_ALLOC);
            if ( !page )
                return -EINVAL;
            nl1e = l1e_from_page(page, l1e_get_flags(nl1e));
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l1e_has_changed(ol1e, nl1e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl1e = adjust_guest_l1e(nl1e, pt_dom);
            rc = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                              preserve_ad);
            if ( page )
                put_page(page);
            return rc ? 0 : -EBUSY;
        }

        switch ( rc = get_page_from_l1e(nl1e, pt_dom, pg_dom) )
        {
        default:
            if ( page )
                put_page(page);
            return rc;
        case 0:
            break;
        case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
            ASSERT(!(rc & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
            l1e_flip_flags(nl1e, rc);
            rc = 0;
            break;
        }
        if ( page )
            put_page(page);

        nl1e = adjust_guest_l1e(nl1e, pt_dom);
        if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                    preserve_ad)) )
        {
            ol1e = nl1e;
            rc = -EBUSY;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                     preserve_ad)) )
    {
        return -EBUSY;
    }

    put_page_from_l1e(ol1e, pt_dom);
    return rc;
}

/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e, l2_pgentry_t nl2e,
                        unsigned long pfn, int preserve_ad, struct vcpu *vcpu)
{
    l2_pgentry_t ol2e;
    struct domain *d = vcpu->domain;
    struct page_info *l2pg = mfn_to_page(_mfn(pfn));
    unsigned long type = l2pg->u.inuse.type_info;
    int rc = 0;

    if ( unlikely(!is_guest_l2_slot(d, type, pgentry_ptr_to_slot(pl2e))) )
    {
        gdprintk(XENLOG_WARNING, "L2 update in Xen-private area, slot %#lx\n",
                 pgentry_ptr_to_slot(pl2e));
        return -EPERM;
    }

    if ( unlikely(__copy_from_user(&ol2e, pl2e, sizeof(ol2e)) != 0) )
        return -EFAULT;

    if ( l2e_get_flags(nl2e) & _PAGE_PRESENT )
    {
        if ( unlikely(l2e_get_flags(nl2e) & L2_DISALLOW_MASK) )
        {
            gdprintk(XENLOG_WARNING, "Bad L2 flags %x\n",
                    l2e_get_flags(nl2e) & L2_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l2e_has_changed(ol2e, nl2e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl2e = adjust_guest_l2e(nl2e, d);
            if ( UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu, preserve_ad) )
                return 0;
            return -EBUSY;
        }

        if ( unlikely((rc = get_page_from_l2e(nl2e, pfn, d)) < 0) )
            return rc;

        nl2e = adjust_guest_l2e(nl2e, d);
        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol2e = nl2e;
            rc = -EBUSY;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return -EBUSY;
    }

    put_page_from_l2e(ol2e, pfn);
    return rc;
}

/* Update the L3 entry at pl3e to new value nl3e. pl3e is within frame pfn. */
static int mod_l3_entry(l3_pgentry_t *pl3e, l3_pgentry_t nl3e,
                        unsigned long pfn, int preserve_ad, struct vcpu *vcpu)
{
    l3_pgentry_t ol3e;
    struct domain *d = vcpu->domain;
    int rc = 0;

    /*
     * Disallow updates to final L3 slot. It contains Xen mappings, and it
     * would be a pain to ensure they remain continuously valid throughout.
     */
    if ( is_pv_32bit_domain(d) && (pgentry_ptr_to_slot(pl3e) >= 3) )
        return -EINVAL;

    if ( unlikely(__copy_from_user(&ol3e, pl3e, sizeof(ol3e)) != 0) )
        return -EFAULT;

    if ( l3e_get_flags(nl3e) & _PAGE_PRESENT )
    {
        if ( unlikely(l3e_get_flags(nl3e) & l3_disallow_mask(d)) )
        {
            gdprintk(XENLOG_WARNING, "Bad L3 flags %x\n",
                    l3e_get_flags(nl3e) & l3_disallow_mask(d));
            return -EINVAL;
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l3e_has_changed(ol3e, nl3e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl3e = adjust_guest_l3e(nl3e, d);
            rc = UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }

        rc = get_page_from_l3e(nl3e, pfn, d, 0);
        if ( unlikely(rc < 0) )
            return rc;
        rc = 0;

        nl3e = adjust_guest_l3e(nl3e, d);
        if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol3e = nl3e;
            rc = -EFAULT;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return -EFAULT;
    }

    if ( likely(rc == 0) )
        if ( !create_pae_xen_mappings(d, pl3e) )
            BUG();

    put_page_from_l3e(ol3e, pfn, 0, 1);
    return rc;
}

/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(l4_pgentry_t *pl4e, l4_pgentry_t nl4e,
                        unsigned long pfn, int preserve_ad, struct vcpu *vcpu)
{
    struct domain *d = vcpu->domain;
    l4_pgentry_t ol4e;
    int rc = 0;

    if ( unlikely(!is_guest_l4_slot(d, pgentry_ptr_to_slot(pl4e))) )
    {
        gdprintk(XENLOG_WARNING, "L4 update in Xen-private area, slot %#lx\n",
                 pgentry_ptr_to_slot(pl4e));
        return -EINVAL;
    }

    if ( unlikely(__copy_from_user(&ol4e, pl4e, sizeof(ol4e)) != 0) )
        return -EFAULT;

    if ( l4e_get_flags(nl4e) & _PAGE_PRESENT )
    {
        if ( unlikely(l4e_get_flags(nl4e) & L4_DISALLOW_MASK) )
        {
            gdprintk(XENLOG_WARNING, "Bad L4 flags %x\n",
                    l4e_get_flags(nl4e) & L4_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l4e_has_changed(ol4e, nl4e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl4e = adjust_guest_l4e(nl4e, d);
            rc = UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }

        rc = get_page_from_l4e(nl4e, pfn, d, 0);
        if ( unlikely(rc < 0) )
            return rc;
        rc = 0;

        nl4e = adjust_guest_l4e(nl4e, d);
        if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol4e = nl4e;
            rc = -EFAULT;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return -EFAULT;
    }

    put_page_from_l4e(ol4e, pfn, 0, 1);
    return rc;
}

int new_guest_cr3(mfn_t mfn)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    int rc;
    mfn_t old_base_mfn;

    if ( is_pv_32bit_domain(currd) )
    {
        mfn_t gt_mfn = pagetable_get_mfn(curr->arch.guest_table);
        l4_pgentry_t *pl4e = map_domain_page(gt_mfn);

        rc = mod_l4_entry(pl4e,
                          l4e_from_mfn(mfn,
                                       (_PAGE_PRESENT | _PAGE_RW |
                                        _PAGE_USER | _PAGE_ACCESSED)),
                          mfn_x(gt_mfn), 0, curr);
        unmap_domain_page(pl4e);
        switch ( rc )
        {
        case 0:
            break;
        case -EINTR:
        case -ERESTART:
            return -ERESTART;
        default:
            gdprintk(XENLOG_WARNING,
                     "Error while installing new compat baseptr %" PRI_mfn "\n",
                     mfn_x(mfn));
            return rc;
        }

        pv_invalidate_shadow_ldt(curr, 0);
        write_ptbase(curr);

        return 0;
    }

    rc = put_old_guest_table(curr);
    if ( unlikely(rc) )
        return rc;

    old_base_mfn = pagetable_get_mfn(curr->arch.guest_table);
    /*
     * This is particularly important when getting restarted after the
     * previous attempt got preempted in the put-old-MFN phase.
     */
    if ( mfn_eq(old_base_mfn, mfn) )
    {
        write_ptbase(curr);
        return 0;
    }

    rc = paging_mode_refcounts(currd)
         ? (get_page_from_mfn(mfn, currd) ? 0 : -EINVAL)
         : get_page_and_type_from_mfn(mfn, PGT_root_page_table, currd, 0, 1);
    switch ( rc )
    {
    case 0:
        break;
    case -EINTR:
    case -ERESTART:
        return -ERESTART;
    default:
        gdprintk(XENLOG_WARNING,
                 "Error while installing new baseptr %" PRI_mfn "\n",
                 mfn_x(mfn));
        return rc;
    }

    pv_invalidate_shadow_ldt(curr, 0);

    if ( !VM_ASSIST(currd, m2p_strict) && !paging_mode_refcounts(currd) )
        fill_ro_mpt(mfn);
    curr->arch.guest_table = pagetable_from_mfn(mfn);
    update_cr3(curr);

    write_ptbase(curr);

    if ( likely(mfn_x(old_base_mfn) != 0) )
    {
        struct page_info *page = mfn_to_page(old_base_mfn);

        if ( paging_mode_refcounts(currd) )
            put_page(page);
        else
            switch ( rc = put_page_and_type_preemptible(page) )
            {
            case -EINTR:
                rc = -ERESTART;
                /* fallthrough */
            case -ERESTART:
                curr->arch.old_guest_table = page;
                break;
            default:
                BUG_ON(rc);
                break;
            }
    }

    return rc;
}

long do_mmuext_op(XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count,
                  XEN_GUEST_HANDLE_PARAM(uint) pdone, unsigned int foreigndom)
{
    struct mmuext_op op;
    unsigned long type;
    unsigned int i, done = 0;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct domain *pg_owner;
    int rc = put_old_guest_table(curr);

    if ( unlikely(rc) )
    {
        if ( likely(rc == -ERESTART) )
            rc = hypercall_create_continuation(
                     __HYPERVISOR_mmuext_op, "hihi", uops, count, pdone,
                     foreigndom);
        return rc;
    }

    if ( unlikely(count == MMU_UPDATE_PREEMPTED) &&
         likely(guest_handle_is_null(uops)) )
    {
        /*
         * See the curr->arch.old_guest_table related
         * hypercall_create_continuation() below.
         */
        return (int)foreigndom;
    }

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }
    else
        perfc_incr(calls_to_mmuext_op);

    if ( unlikely(!guest_handle_okay(uops, count)) )
        return -EFAULT;

    if ( (pg_owner = get_pg_owner(foreigndom)) == NULL )
        return -ESRCH;

    if ( !is_pv_domain(pg_owner) )
    {
        put_pg_owner(pg_owner);
        return -EINVAL;
    }

    rc = xsm_mmuext_op(XSM_TARGET, currd, pg_owner);
    if ( rc )
    {
        put_pg_owner(pg_owner);
        return rc;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( curr->arch.old_guest_table || (i && hypercall_preempt_check()) )
        {
            rc = -ERESTART;
            break;
        }

        if ( unlikely(__copy_from_guest(&op, uops, 1) != 0) )
        {
            rc = -EFAULT;
            break;
        }

        if ( is_hvm_domain(currd) )
        {
            switch ( op.cmd )
            {
            case MMUEXT_PIN_L1_TABLE:
            case MMUEXT_PIN_L2_TABLE:
            case MMUEXT_PIN_L3_TABLE:
            case MMUEXT_PIN_L4_TABLE:
            case MMUEXT_UNPIN_TABLE:
                break;
            default:
                rc = -EOPNOTSUPP;
                goto done;
            }
        }

        rc = 0;

        switch ( op.cmd )
        {
            struct page_info *page;
            p2m_type_t p2mt;

        case MMUEXT_PIN_L1_TABLE:
            type = PGT_l1_page_table;
            goto pin_page;

        case MMUEXT_PIN_L2_TABLE:
            type = PGT_l2_page_table;
            goto pin_page;

        case MMUEXT_PIN_L3_TABLE:
            type = PGT_l3_page_table;
            goto pin_page;

        case MMUEXT_PIN_L4_TABLE:
            if ( is_pv_32bit_domain(pg_owner) )
                break;
            type = PGT_l4_page_table;

        pin_page:
            /* Ignore pinning of invalid paging levels. */
            if ( (op.cmd - MMUEXT_PIN_L1_TABLE) > (CONFIG_PAGING_LEVELS - 1) )
                break;

            if ( paging_mode_refcounts(pg_owner) )
                break;

            page = get_page_from_gfn(pg_owner, op.arg1.mfn, NULL, P2M_ALLOC);
            if ( unlikely(!page) )
            {
                rc = -EINVAL;
                break;
            }

            rc = get_page_type_preemptible(page, type);
            if ( unlikely(rc) )
            {
                if ( rc == -EINTR )
                    rc = -ERESTART;
                else if ( rc != -ERESTART )
                    gdprintk(XENLOG_WARNING,
                             "Error %d while pinning mfn %" PRI_mfn "\n",
                             rc, mfn_x(page_to_mfn(page)));
                if ( page != curr->arch.old_guest_table )
                    put_page(page);
                break;
            }

            rc = xsm_memory_pin_page(XSM_HOOK, currd, pg_owner, page);
            if ( !rc && unlikely(test_and_set_bit(_PGT_pinned,
                                                  &page->u.inuse.type_info)) )
            {
                gdprintk(XENLOG_WARNING,
                         "mfn %" PRI_mfn " already pinned\n",
                         mfn_x(page_to_mfn(page)));
                rc = -EINVAL;
            }

            if ( unlikely(rc) )
                goto pin_drop;

            /* A page is dirtied when its pin status is set. */
            paging_mark_dirty(pg_owner, page_to_mfn(page));

            /* We can race domain destruction (domain_relinquish_resources). */
            if ( unlikely(pg_owner != currd) )
            {
                bool drop_ref;

                spin_lock(&pg_owner->page_alloc_lock);
                drop_ref = (pg_owner->is_dying &&
                            test_and_clear_bit(_PGT_pinned,
                                               &page->u.inuse.type_info));
                spin_unlock(&pg_owner->page_alloc_lock);
                if ( drop_ref )
                {
        pin_drop:
                    if ( type == PGT_l1_page_table )
                        put_page_and_type(page);
                    else
                        curr->arch.old_guest_table = page;
                }
            }
            break;

        case MMUEXT_UNPIN_TABLE:
            if ( paging_mode_refcounts(pg_owner) )
                break;

            page = get_page_from_gfn(pg_owner, op.arg1.mfn, NULL, P2M_ALLOC);
            if ( unlikely(!page) )
            {
                gdprintk(XENLOG_WARNING,
                         "mfn %" PRI_mfn " bad, or bad owner d%d\n",
                         op.arg1.mfn, pg_owner->domain_id);
                rc = -EINVAL;
                break;
            }

            if ( !test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            {
                put_page(page);
                gdprintk(XENLOG_WARNING,
                         "mfn %" PRI_mfn " not pinned\n", op.arg1.mfn);
                rc = -EINVAL;
                break;
            }

            switch ( rc = put_page_and_type_preemptible(page) )
            {
            case -EINTR:
            case -ERESTART:
                curr->arch.old_guest_table = page;
                rc = 0;
                break;
            default:
                BUG_ON(rc);
                break;
            }
            put_page(page);

            /* A page is dirtied when its pin status is cleared. */
            paging_mark_dirty(pg_owner, page_to_mfn(page));
            break;

        case MMUEXT_NEW_BASEPTR:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(paging_mode_translate(currd)) )
                rc = -EINVAL;
            else
                rc = new_guest_cr3(_mfn(op.arg1.mfn));
            break;

        case MMUEXT_NEW_USER_BASEPTR: {
            unsigned long old_mfn;

            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(paging_mode_translate(currd)) )
                rc = -EINVAL;
            if ( unlikely(rc) )
                break;

            old_mfn = pagetable_get_pfn(curr->arch.guest_table_user);
            /*
             * This is particularly important when getting restarted after the
             * previous attempt got preempted in the put-old-MFN phase.
             */
            if ( old_mfn == op.arg1.mfn )
                break;

            if ( op.arg1.mfn != 0 )
            {
                rc = get_page_and_type_from_mfn(
                    _mfn(op.arg1.mfn), PGT_root_page_table, currd, 0, 1);

                if ( unlikely(rc) )
                {
                    if ( rc == -EINTR )
                        rc = -ERESTART;
                    else if ( rc != -ERESTART )
                        gdprintk(XENLOG_WARNING,
                                 "Error %d installing new mfn %" PRI_mfn "\n",
                                 rc, op.arg1.mfn);
                    break;
                }

                if ( VM_ASSIST(currd, m2p_strict) )
                    zap_ro_mpt(_mfn(op.arg1.mfn));
            }

            curr->arch.guest_table_user = pagetable_from_pfn(op.arg1.mfn);

            if ( old_mfn != 0 )
            {
                page = mfn_to_page(_mfn(old_mfn));

                switch ( rc = put_page_and_type_preemptible(page) )
                {
                case -EINTR:
                    rc = -ERESTART;
                    /* fallthrough */
                case -ERESTART:
                    curr->arch.old_guest_table = page;
                    break;
                default:
                    BUG_ON(rc);
                    break;
                }
            }

            break;
        }

        case MMUEXT_TLB_FLUSH_LOCAL:
            if ( likely(currd == pg_owner) )
                flush_tlb_local();
            else
                rc = -EPERM;
            break;

        case MMUEXT_INVLPG_LOCAL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else
                paging_invlpg(curr, op.arg1.linear_addr);
            break;

        case MMUEXT_TLB_FLUSH_MULTI:
        case MMUEXT_INVLPG_MULTI:
        {
            cpumask_t *mask = this_cpu(scratch_cpumask);

            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(vcpumask_to_pcpumask(currd,
                                   guest_handle_to_param(op.arg2.vcpumask,
                                                         const_void),
                                   mask)) )
                rc = -EINVAL;
            if ( unlikely(rc) )
                break;

            if ( op.cmd == MMUEXT_TLB_FLUSH_MULTI )
                flush_tlb_mask(mask);
            else if ( __addr_ok(op.arg1.linear_addr) )
                flush_tlb_one_mask(mask, op.arg1.linear_addr);
            break;
        }

        case MMUEXT_TLB_FLUSH_ALL:
            if ( likely(currd == pg_owner) )
                flush_tlb_mask(currd->domain_dirty_cpumask);
            else
                rc = -EPERM;
            break;

        case MMUEXT_INVLPG_ALL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( __addr_ok(op.arg1.linear_addr) )
                flush_tlb_one_mask(currd->domain_dirty_cpumask,
                                   op.arg1.linear_addr);
            break;

        case MMUEXT_FLUSH_CACHE:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(!cache_flush_permitted(currd)) )
                rc = -EACCES;
            else
                wbinvd();
            break;

        case MMUEXT_FLUSH_CACHE_GLOBAL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( likely(cache_flush_permitted(currd)) )
            {
                unsigned int cpu;
                cpumask_t *mask = this_cpu(scratch_cpumask);

                cpumask_clear(mask);
                for_each_online_cpu(cpu)
                    if ( !cpumask_intersects(mask,
                                             per_cpu(cpu_sibling_mask, cpu)) )
                        __cpumask_set_cpu(cpu, mask);
                flush_mask(mask, FLUSH_CACHE);
            }
            else
                rc = -EINVAL;
            break;

        case MMUEXT_SET_LDT:
        {
            unsigned int ents = op.arg2.nr_ents;
            unsigned long ptr = ents ? op.arg1.linear_addr : 0;

            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( paging_mode_external(currd) )
                rc = -EINVAL;
            else if ( ((ptr & (PAGE_SIZE - 1)) != 0) || !__addr_ok(ptr) ||
                      (ents > 8192) )
            {
                gdprintk(XENLOG_WARNING,
                         "Bad args to SET_LDT: ptr=%lx, ents=%x\n", ptr, ents);
                rc = -EINVAL;
            }
            else if ( (curr->arch.pv_vcpu.ldt_ents != ents) ||
                      (curr->arch.pv_vcpu.ldt_base != ptr) )
            {
                pv_invalidate_shadow_ldt(curr, 0);
                flush_tlb_local();
                curr->arch.pv_vcpu.ldt_base = ptr;
                curr->arch.pv_vcpu.ldt_ents = ents;
                load_LDT(curr);
            }
            break;
        }

        case MMUEXT_CLEAR_PAGE:
            page = get_page_from_gfn(pg_owner, op.arg1.mfn, &p2mt, P2M_ALLOC);
            if ( unlikely(p2mt != p2m_ram_rw) && page )
            {
                put_page(page);
                page = NULL;
            }
            if ( !page || !get_page_type(page, PGT_writable_page) )
            {
                if ( page )
                    put_page(page);
                gdprintk(XENLOG_WARNING,
                         "Error clearing mfn %" PRI_mfn "\n", op.arg1.mfn);
                rc = -EINVAL;
                break;
            }

            /* A page is dirtied when it's being cleared. */
            paging_mark_dirty(pg_owner, page_to_mfn(page));

            clear_domain_page(page_to_mfn(page));

            put_page_and_type(page);
            break;

        case MMUEXT_COPY_PAGE:
        {
            struct page_info *src_page, *dst_page;

            src_page = get_page_from_gfn(pg_owner, op.arg2.src_mfn, &p2mt,
                                         P2M_ALLOC);
            if ( unlikely(p2mt != p2m_ram_rw) && src_page )
            {
                put_page(src_page);
                src_page = NULL;
            }
            if ( unlikely(!src_page) )
            {
                gdprintk(XENLOG_WARNING,
                         "Error copying from mfn %" PRI_mfn "\n",
                         op.arg2.src_mfn);
                rc = -EINVAL;
                break;
            }

            dst_page = get_page_from_gfn(pg_owner, op.arg1.mfn, &p2mt,
                                         P2M_ALLOC);
            if ( unlikely(p2mt != p2m_ram_rw) && dst_page )
            {
                put_page(dst_page);
                dst_page = NULL;
            }
            rc = (dst_page &&
                  get_page_type(dst_page, PGT_writable_page)) ? 0 : -EINVAL;
            if ( unlikely(rc) )
            {
                put_page(src_page);
                if ( dst_page )
                    put_page(dst_page);
                gdprintk(XENLOG_WARNING,
                         "Error copying to mfn %" PRI_mfn "\n", op.arg1.mfn);
                break;
            }

            /* A page is dirtied when it's being copied to. */
            paging_mark_dirty(pg_owner, page_to_mfn(dst_page));

            copy_domain_page(page_to_mfn(dst_page), page_to_mfn(src_page));

            put_page_and_type(dst_page);
            put_page(src_page);
            break;
        }

        case MMUEXT_MARK_SUPER:
        case MMUEXT_UNMARK_SUPER:
            rc = -EOPNOTSUPP;
            break;

        default:
            rc = -ENOSYS;
            break;
        }

 done:
        if ( unlikely(rc) )
            break;

        guest_handle_add_offset(uops, 1);
    }

    if ( rc == -ERESTART )
    {
        ASSERT(i < count);
        rc = hypercall_create_continuation(
            __HYPERVISOR_mmuext_op, "hihi",
            uops, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
    }
    else if ( curr->arch.old_guest_table )
    {
        XEN_GUEST_HANDLE_PARAM(void) null;

        ASSERT(rc || i == count);
        set_xen_guest_handle(null, NULL);
        /*
         * In order to have a way to communicate the final return value to
         * our continuation, we pass this in place of "foreigndom", building
         * on the fact that this argument isn't needed anymore.
         */
        rc = hypercall_create_continuation(
                __HYPERVISOR_mmuext_op, "hihi", null,
                MMU_UPDATE_PREEMPTED, null, rc);
    }

    put_pg_owner(pg_owner);

    perfc_add(num_mmuext_ops, i);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(!guest_handle_is_null(pdone)) )
    {
        done += i;
        copy_to_guest(pdone, &done, 1);
    }

    return rc;
}

long do_mmu_update(XEN_GUEST_HANDLE_PARAM(mmu_update_t) ureqs,
                   unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone,
                   unsigned int foreigndom)
{
    struct mmu_update req;
    void *va = NULL;
    unsigned long gpfn, gmfn, mfn;
    struct page_info *page;
    unsigned int cmd, i = 0, done = 0, pt_dom;
    struct vcpu *curr = current, *v = curr;
    struct domain *d = v->domain, *pt_owner = d, *pg_owner;
    mfn_t map_mfn = INVALID_MFN;
    uint32_t xsm_needed = 0;
    uint32_t xsm_checked = 0;
    int rc = put_old_guest_table(curr);

    if ( unlikely(rc) )
    {
        if ( likely(rc == -ERESTART) )
            rc = hypercall_create_continuation(
                     __HYPERVISOR_mmu_update, "hihi", ureqs, count, pdone,
                     foreigndom);
        return rc;
    }

    if ( unlikely(count == MMU_UPDATE_PREEMPTED) &&
         likely(guest_handle_is_null(ureqs)) )
    {
        /*
         * See the curr->arch.old_guest_table related
         * hypercall_create_continuation() below.
         */
        return (int)foreigndom;
    }

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }
    else
        perfc_incr(calls_to_mmu_update);

    if ( unlikely(!guest_handle_okay(ureqs, count)) )
        return -EFAULT;

    if ( (pt_dom = foreigndom >> 16) != 0 )
    {
        /* Pagetables belong to a foreign domain (PFD). */
        if ( (pt_owner = rcu_lock_domain_by_id(pt_dom - 1)) == NULL )
            return -ESRCH;

        if ( pt_owner == d )
            rcu_unlock_domain(pt_owner);
        else if ( !pt_owner->vcpu || (v = pt_owner->vcpu[0]) == NULL )
        {
            rc = -EINVAL;
            goto out;
        }
    }

    if ( (pg_owner = get_pg_owner((uint16_t)foreigndom)) == NULL )
    {
        rc = -ESRCH;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( curr->arch.old_guest_table || (i && hypercall_preempt_check()) )
        {
            rc = -ERESTART;
            break;
        }

        if ( unlikely(__copy_from_guest(&req, ureqs, 1) != 0) )
        {
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);

        switch ( cmd )
        {
            /*
             * MMU_NORMAL_PT_UPDATE: Normal update to any level of page table.
             * MMU_UPDATE_PT_PRESERVE_AD: As above but also preserve (OR)
             * current A/D bits.
             */
        case MMU_NORMAL_PT_UPDATE:
        case MMU_PT_UPDATE_PRESERVE_AD:
        {
            p2m_type_t p2mt;

            rc = -EOPNOTSUPP;
            if ( unlikely(paging_mode_refcounts(pt_owner)) )
                break;

            xsm_needed |= XSM_MMU_NORMAL_UPDATE;
            if ( get_pte_flags(req.val) & _PAGE_PRESENT )
            {
                xsm_needed |= XSM_MMU_UPDATE_READ;
                if ( get_pte_flags(req.val) & _PAGE_RW )
                    xsm_needed |= XSM_MMU_UPDATE_WRITE;
            }
            if ( xsm_needed != xsm_checked )
            {
                rc = xsm_mmu_update(XSM_TARGET, d, pt_owner, pg_owner, xsm_needed);
                if ( rc )
                    break;
                xsm_checked = xsm_needed;
            }
            rc = -EINVAL;

            req.ptr -= cmd;
            gmfn = req.ptr >> PAGE_SHIFT;
            page = get_page_from_gfn(pt_owner, gmfn, &p2mt, P2M_ALLOC);

            if ( p2m_is_paged(p2mt) )
            {
                ASSERT(!page);
                p2m_mem_paging_populate(pg_owner, gmfn);
                rc = -ENOENT;
                break;
            }

            if ( unlikely(!page) )
            {
                gdprintk(XENLOG_WARNING,
                         "Could not get page for normal update\n");
                break;
            }

            mfn = mfn_x(page_to_mfn(page));

            if ( !mfn_eq(_mfn(mfn), map_mfn) )
            {
                if ( va )
                    unmap_domain_page(va);
                va = map_domain_page(_mfn(mfn));
                map_mfn = _mfn(mfn);
            }
            va = _p(((unsigned long)va & PAGE_MASK) + (req.ptr & ~PAGE_MASK));

            if ( page_lock(page) )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                {
                    l1_pgentry_t l1e = l1e_from_intpte(req.val);
                    p2m_type_t l1e_p2mt = p2m_ram_rw;
                    struct page_info *target = NULL;
                    p2m_query_t q = (l1e_get_flags(l1e) & _PAGE_RW) ?
                                        P2M_UNSHARE : P2M_ALLOC;

                    if ( paging_mode_translate(pg_owner) )
                        target = get_page_from_gfn(pg_owner, l1e_get_pfn(l1e),
                                                   &l1e_p2mt, q);

                    if ( p2m_is_paged(l1e_p2mt) )
                    {
                        if ( target )
                            put_page(target);
                        p2m_mem_paging_populate(pg_owner, l1e_get_pfn(l1e));
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_paging_in == l1e_p2mt && !target )
                    {
                        rc = -ENOENT;
                        break;
                    }
                    /* If we tried to unshare and failed */
                    else if ( (q & P2M_UNSHARE) && p2m_is_shared(l1e_p2mt) )
                    {
                        /* We could not have obtained a page ref. */
                        ASSERT(target == NULL);
                        /* And mem_sharing_notify has already been called. */
                        rc = -ENOMEM;
                        break;
                    }

                    rc = mod_l1_entry(va, l1e, mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v,
                                      pg_owner);
                    if ( target )
                        put_page(target);
                }
                break;
                case PGT_l2_page_table:
                    rc = mod_l2_entry(va, l2e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    break;
                case PGT_l3_page_table:
                    rc = mod_l3_entry(va, l3e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    break;
                case PGT_l4_page_table:
                    rc = mod_l4_entry(va, l4e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                break;
                case PGT_writable_page:
                    perfc_incr(writable_mmu_updates);
                    if ( paging_write_guest_entry(v, va, req.val, _mfn(mfn)) )
                        rc = 0;
                    break;
                }
                page_unlock(page);
                if ( rc == -EINTR )
                    rc = -ERESTART;
            }
            else if ( get_page_type(page, PGT_writable_page) )
            {
                perfc_incr(writable_mmu_updates);
                if ( paging_write_guest_entry(v, va, req.val, _mfn(mfn)) )
                    rc = 0;
                put_page_type(page);
            }

            put_page(page);
        }
        break;

        case MMU_MACHPHYS_UPDATE:
            if ( unlikely(d != pt_owner) )
            {
                rc = -EPERM;
                break;
            }

            if ( unlikely(paging_mode_translate(pg_owner)) )
            {
                rc = -EINVAL;
                break;
            }

            mfn = req.ptr >> PAGE_SHIFT;
            gpfn = req.val;

            xsm_needed |= XSM_MMU_MACHPHYS_UPDATE;
            if ( xsm_needed != xsm_checked )
            {
                rc = xsm_mmu_update(XSM_TARGET, d, NULL, pg_owner, xsm_needed);
                if ( rc )
                    break;
                xsm_checked = xsm_needed;
            }

            if ( unlikely(!get_page_from_mfn(_mfn(mfn), pg_owner)) )
            {
                gdprintk(XENLOG_WARNING,
                         "Could not get page for mach->phys update\n");
                rc = -EINVAL;
                break;
            }

            set_gpfn_from_mfn(mfn, gpfn);

            paging_mark_dirty(pg_owner, _mfn(mfn));

            put_page(mfn_to_page(_mfn(mfn)));
            break;

        default:
            rc = -ENOSYS;
            break;
        }

        if ( unlikely(rc) )
            break;

        guest_handle_add_offset(ureqs, 1);
    }

    if ( rc == -ERESTART )
    {
        ASSERT(i < count);
        rc = hypercall_create_continuation(
            __HYPERVISOR_mmu_update, "hihi",
            ureqs, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
    }
    else if ( curr->arch.old_guest_table )
    {
        XEN_GUEST_HANDLE_PARAM(void) null;

        ASSERT(rc || i == count);
        set_xen_guest_handle(null, NULL);
        /*
         * In order to have a way to communicate the final return value to
         * our continuation, we pass this in place of "foreigndom", building
         * on the fact that this argument isn't needed anymore.
         */
        rc = hypercall_create_continuation(
                __HYPERVISOR_mmu_update, "hihi", null,
                MMU_UPDATE_PREEMPTED, null, rc);
    }

    put_pg_owner(pg_owner);

    if ( va )
        unmap_domain_page(va);

    perfc_add(num_page_updates, i);

 out:
    if ( pt_owner != d )
        rcu_unlock_domain(pt_owner);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(!guest_handle_is_null(pdone)) )
    {
        done += i;
        copy_to_guest(pdone, &done, 1);
    }

    return rc;
}

static int __do_update_va_mapping(unsigned long va, uint64_t val64,
                                  unsigned long flags, struct domain *pg_owner)
{
    l1_pgentry_t   val = l1e_from_intpte(val64);
    struct vcpu   *curr = current;
    struct domain *currd = curr->domain;
    struct page_info *gl1pg;
    l1_pgentry_t  *pl1e;
    unsigned long  bmap_ptr;
    mfn_t          gl1mfn;
    cpumask_t     *mask = NULL;
    int            rc;

    perfc_incr(calls_to_update_va);

    rc = xsm_update_va_mapping(XSM_TARGET, currd, pg_owner, val);
    if ( rc )
        return rc;

    rc = -EINVAL;
    pl1e = map_guest_l1e(va, &gl1mfn);
    if ( unlikely(!pl1e || !get_page_from_mfn(gl1mfn, currd)) )
        goto out;

    gl1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(gl1pg) )
    {
        put_page(gl1pg);
        goto out;
    }

    if ( (gl1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(gl1pg);
        put_page(gl1pg);
        goto out;
    }

    rc = mod_l1_entry(pl1e, val, mfn_x(gl1mfn), 0, curr, pg_owner);

    page_unlock(gl1pg);
    put_page(gl1pg);

 out:
    if ( pl1e )
        unmap_domain_page(pl1e);

    switch ( flags & UVMF_FLUSHTYPE_MASK )
    {
    case UVMF_TLB_FLUSH:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            flush_tlb_local();
            break;
        case UVMF_ALL:
            mask = currd->domain_dirty_cpumask;
            break;
        default:
            mask = this_cpu(scratch_cpumask);
            rc = vcpumask_to_pcpumask(currd,
                                      const_guest_handle_from_ptr(bmap_ptr, void),
                                      mask);
            break;
        }
        if ( mask )
            flush_tlb_mask(mask);
        break;

    case UVMF_INVLPG:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            paging_invlpg(curr, va);
            break;
        case UVMF_ALL:
            mask = currd->domain_dirty_cpumask;
            break;
        default:
            mask = this_cpu(scratch_cpumask);
            rc = vcpumask_to_pcpumask(currd,
                                      const_guest_handle_from_ptr(bmap_ptr, void),
                                      mask);
            break;
        }
        if ( mask )
            flush_tlb_one_mask(mask, va);
        break;
    }

    return rc;
}

long do_update_va_mapping(unsigned long va, uint64_t val64,
                          unsigned long flags)
{
    return __do_update_va_mapping(va, val64, flags, current->domain);
}

long do_update_va_mapping_otherdomain(unsigned long va, uint64_t val64,
                                      unsigned long flags,
                                      domid_t domid)
{
    struct domain *pg_owner;
    int rc;

    if ( (pg_owner = get_pg_owner(domid)) == NULL )
        return -ESRCH;

    rc = __do_update_va_mapping(va, val64, flags, pg_owner);

    put_pg_owner(pg_owner);

    return rc;
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
