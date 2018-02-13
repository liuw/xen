/*
 * pv/mm.c
 *
 * Memory managment code for PV guests
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xsm/xsm.h>

#include <asm/current.h>
#include <asm/event.h>
#include <asm/iocap.h>
#include <asm/ldt.h>
#include <asm/p2m.h>
#include <asm/pv/mm.h>
#include <asm/shadow.h>

#include "mm.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

/*
 * Get a mapping of a PV guest's l1e for this linear address.  The return
 * pointer should be unmapped using unmap_domain_page().
 */
l1_pgentry_t *map_guest_l1e(unsigned long linear, mfn_t *gl1mfn)
{
    l2_pgentry_t l2e;

    ASSERT(!paging_mode_translate(current->domain));
    ASSERT(!paging_mode_external(current->domain));

    if ( unlikely(!__addr_ok(linear)) )
        return NULL;

    /* Find this l1e and its enclosing l1mfn in the linear map. */
    if ( __copy_from_user(&l2e,
                          &__linear_l2_table[l2_linear_offset(linear)],
                          sizeof(l2_pgentry_t)) )
        return NULL;

    /* Check flags that it will be safe to read the l1e. */
    if ( (l2e_get_flags(l2e) & (_PAGE_PRESENT | _PAGE_PSE)) != _PAGE_PRESENT )
        return NULL;

    *gl1mfn = l2e_get_mfn(l2e);

    return (l1_pgentry_t *)map_domain_page(*gl1mfn) + l1_table_offset(linear);
}

/*
 * Read the guest's l1e that maps this address, from the kernel-mode
 * page tables.
 */
static l1_pgentry_t guest_get_eff_kern_l1e(unsigned long linear)
{
    struct vcpu *curr = current;
    const bool user_mode = !(curr->arch.flags & TF_kernel_mode);
    l1_pgentry_t l1e;

    if ( user_mode )
        toggle_guest_pt(curr);

    l1e = guest_get_eff_l1e(linear);

    if ( user_mode )
        toggle_guest_pt(curr);

    return l1e;
}

/*
 * Map a guest's LDT page (covering the byte at @offset from start of the LDT)
 * into Xen's virtual range.  Returns true if the mapping changed, false
 * otherwise.
 */
bool pv_map_ldt_shadow_page(unsigned int offset)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct page_info *page;
    l1_pgentry_t gl1e, *pl1e;
    unsigned long linear = curr->arch.pv_vcpu.ldt_base + offset;

    BUG_ON(unlikely(in_irq()));

    /*
     * Hardware limit checking should guarantee this property.  NB. This is
     * safe as updates to the LDT can only be made by MMUEXT_SET_LDT to the
     * current vcpu, and vcpu_reset() will block until this vcpu has been
     * descheduled before continuing.
     */
    ASSERT((offset >> 3) <= curr->arch.pv_vcpu.ldt_ents);

    if ( is_pv_32bit_domain(currd) )
        linear = (uint32_t)linear;

    gl1e = guest_get_eff_kern_l1e(linear);
    if ( unlikely(!(l1e_get_flags(gl1e) & _PAGE_PRESENT)) )
        return false;

    page = get_page_from_gfn(currd, l1e_get_pfn(gl1e), NULL, P2M_ALLOC);
    if ( unlikely(!page) )
        return false;

    if ( unlikely(!get_page_type(page, PGT_seg_desc_page)) )
    {
        put_page(page);
        return false;
    }

    pl1e = &pv_ldt_ptes(curr)[offset >> PAGE_SHIFT];
    l1e_add_flags(gl1e, _PAGE_RW);

    spin_lock(&curr->arch.pv_vcpu.shadow_ldt_lock);
    l1e_write(pl1e, gl1e);
    curr->arch.pv_vcpu.shadow_ldt_mapcnt++;
    spin_unlock(&curr->arch.pv_vcpu.shadow_ldt_lock);

    return true;
}

/*
 * PTE flags that a guest may change without re-validating the PTE.
 * All other bits affect translation, caching, or Xen's safety.
 */
#define FASTPATH_FLAG_WHITELIST                                     \
    (_PAGE_NX_BIT | _PAGE_AVAIL_HIGH | _PAGE_AVAIL | _PAGE_GLOBAL | \
     _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_USER)

static int get_page_and_type_from_mfn(
    mfn_t mfn, unsigned long type, struct domain *d,
    int partial, int preemptible)
{
    struct page_info *page = mfn_to_page(mfn);
    int rc;

    if ( likely(partial >= 0) &&
         unlikely(!get_page_from_mfn(mfn, d)) )
        return -EINVAL;

    rc = (preemptible ?
          get_page_type_preemptible(page, type) :
          (get_page_type(page, type) ? 0 : -EINVAL));

    if ( unlikely(rc) && partial >= 0 &&
         (!preemptible || page != current->arch.old_guest_table) )
        put_page(page);

    return rc;
}

static void put_data_page(
    struct page_info *page, int writeable)
{
    if ( writeable )
        put_page_and_type(page);
    else
        put_page(page);
}

static int create_pae_xen_mappings(struct domain *d, l3_pgentry_t *pl3e)
{
    struct page_info *page;
    l3_pgentry_t     l3e3;

    if ( !is_pv_32bit_domain(d) )
        return 1;

    pl3e = (l3_pgentry_t *)((unsigned long)pl3e & PAGE_MASK);

    /* 3rd L3 slot contains L2 with Xen-private mappings. It *must* exist. */
    l3e3 = pl3e[3];
    if ( !(l3e_get_flags(l3e3) & _PAGE_PRESENT) )
    {
        gdprintk(XENLOG_WARNING, "PAE L3 3rd slot is empty\n");
        return 0;
    }

    /*
     * The Xen-private mappings include linear mappings. The L2 thus cannot
     * be shared by multiple L3 tables. The test here is adequate because:
     *  1. Cannot appear in slots != 3 because get_page_type() checks the
     *     PGT_pae_xen_l2 flag, which is asserted iff the L2 appears in slot 3
     *  2. Cannot appear in another page table's L3:
     *     a. alloc_l3_table() calls this function and this check will fail
     *     b. mod_l3_entry() disallows updates to slot 3 in an existing table
     */
    page = l3e_get_page(l3e3);
    BUG_ON(page->u.inuse.type_info & PGT_pinned);
    BUG_ON((page->u.inuse.type_info & PGT_count_mask) == 0);
    BUG_ON(!(page->u.inuse.type_info & PGT_pae_xen_l2));
    if ( (page->u.inuse.type_info & PGT_count_mask) != 1 )
    {
        gdprintk(XENLOG_WARNING, "PAE L3 3rd slot is shared\n");
        return 0;
    }

    return 1;
}

#ifdef CONFIG_PV_LINEAR_PT

static bool inc_linear_entries(struct page_info *pg)
{
    typeof(pg->linear_pt_count) nc = read_atomic(&pg->linear_pt_count), oc;

    do {
        /*
         * The check below checks for the "linear use" count being non-zero
         * as well as overflow.  Signed integer overflow is undefined behavior
         * according to the C spec.  However, as long as linear_pt_count is
         * smaller in size than 'int', the arithmetic operation of the
         * increment below won't overflow; rather the result will be truncated
         * when stored.  Ensure that this is always true.
         */
        BUILD_BUG_ON(sizeof(nc) >= sizeof(int));
        oc = nc++;
        if ( nc <= 0 )
            return false;
        nc = cmpxchg(&pg->linear_pt_count, oc, nc);
    } while ( oc != nc );

    return true;
}

static void dec_linear_entries(struct page_info *pg)
{
    typeof(pg->linear_pt_count) oc;

    oc = arch_fetch_and_add(&pg->linear_pt_count, -1);
    ASSERT(oc > 0);
}

static bool inc_linear_uses(struct page_info *pg)
{
    typeof(pg->linear_pt_count) nc = read_atomic(&pg->linear_pt_count), oc;

    do {
        /* See the respective comment in inc_linear_entries(). */
        BUILD_BUG_ON(sizeof(nc) >= sizeof(int));
        oc = nc--;
        if ( nc >= 0 )
            return false;
        nc = cmpxchg(&pg->linear_pt_count, oc, nc);
    } while ( oc != nc );

    return true;
}

static void dec_linear_uses(struct page_info *pg)
{
    typeof(pg->linear_pt_count) oc;

    oc = arch_fetch_and_add(&pg->linear_pt_count, 1);
    ASSERT(oc < 0);
}

/*
 * We allow root tables to map each other (a.k.a. linear page tables). It
 * needs some special care with reference counts and access permissions:
 *  1. The mapping entry must be read-only, or the guest may get write access
 *     to its own PTEs.
 *  2. We must only bump the reference counts for an *already validated*
 *     L2 table, or we can end up in a deadlock in get_page_type() by waiting
 *     on a validation that is required to complete that validation.
 *  3. We only need to increment the reference counts for the mapped page
 *     frame if it is mapped by a different root table. This is sufficient and
 *     also necessary to allow validation of a root table mapping itself.
 */
static bool __read_mostly opt_pv_linear_pt = true;
boolean_param("pv-linear-pt", opt_pv_linear_pt);

#define define_get_linear_pagetable(level)                                  \
static int                                                                  \
get_##level##_linear_pagetable(                                             \
    level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d)         \
{                                                                           \
    unsigned long x, y;                                                     \
    unsigned long pfn;                                                      \
                                                                            \
    if ( !opt_pv_linear_pt )                                                \
    {                                                                       \
        gdprintk(XENLOG_WARNING,                                            \
                 "Attempt to create linear p.t. (feature disabled)\n");     \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (level##e_get_flags(pde) & _PAGE_RW) )                             \
    {                                                                       \
        gdprintk(XENLOG_WARNING,                                            \
                 "Attempt to create linear p.t. with write perms\n");       \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (pfn = level##e_get_pfn(pde)) != pde_pfn )                         \
    {                                                                       \
        struct page_info *page, *ptpg = mfn_to_page(_mfn(pde_pfn));         \
                                                                            \
        /* Make sure the page table belongs to the correct domain. */       \
        if ( unlikely(page_get_owner(ptpg) != d) )                          \
            return 0;                                                       \
                                                                            \
        /* Make sure the mapped frame belongs to the correct domain. */     \
        page = get_page_from_mfn(_mfn(pfn), d);                             \
        if ( unlikely(!page) )                                              \
            return 0;                                                       \
                                                                            \
        /*                                                                  \
         * Ensure that the mapped frame is an already-validated page table  \
         * and is not itself having linear entries, as well as that the     \
         * containing page table is not iself in use as a linear page table \
         * elsewhere.                                                       \
         * If so, atomically increment the count (checking for overflow).   \
         */                                                                 \
        if ( !inc_linear_entries(ptpg) )                                    \
        {                                                                   \
            put_page(page);                                                 \
            return 0;                                                       \
        }                                                                   \
        if ( !inc_linear_uses(page) )                                       \
        {                                                                   \
            dec_linear_entries(ptpg);                                       \
            put_page(page);                                                 \
            return 0;                                                       \
        }                                                                   \
        y = page->u.inuse.type_info;                                        \
        do {                                                                \
            x = y;                                                          \
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||        \
                 unlikely((x & (PGT_type_mask|PGT_validated)) !=            \
                          (PGT_##level##_page_table|PGT_validated)) )       \
            {                                                               \
                dec_linear_uses(page);                                      \
                dec_linear_entries(ptpg);                                   \
                put_page(page);                                             \
                return 0;                                                   \
            }                                                               \
        }                                                                   \
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );   \
    }                                                                       \
                                                                            \
    return 1;                                                               \
}

#else /* CONFIG_PV_LINEAR_PT */

#define define_get_linear_pagetable(level)                              \
static int                                                              \
get_##level##_linear_pagetable(                                         \
        level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d) \
{                                                                       \
        return 0;                                                       \
}

static void dec_linear_uses(struct page_info *pg)
{
    ASSERT(pg->linear_pt_count == 0);
}

static void dec_linear_entries(struct page_info *pg)
{
    ASSERT(pg->linear_pt_count == 0);
}

#endif /* CONFIG_PV_LINEAR_PT */

/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
/*
 * get_page_from_l2e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l2);
static int
get_page_from_l2e(
    l2_pgentry_t l2e, unsigned long pfn, struct domain *d)
{
    unsigned long mfn = l2e_get_pfn(l2e);
    int rc;

    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2e_get_flags(l2e) & L2_DISALLOW_MASK)) )
    {
        gdprintk(XENLOG_WARNING, "Bad L2 flags %x\n",
                 l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return -EINVAL;
    }

    rc = get_page_and_type_from_mfn(_mfn(mfn), PGT_l1_page_table, d, 0, 0);
    if ( unlikely(rc == -EINVAL) && get_l2_linear_pagetable(l2e, pfn, d) )
        rc = 0;

    return rc;
}


/*
 * get_page_from_l3e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l3);
static int
get_page_from_l3e(
    l3_pgentry_t l3e, unsigned long pfn, struct domain *d, int partial)
{
    int rc;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l3e_get_flags(l3e) & l3_disallow_mask(d))) )
    {
        gdprintk(XENLOG_WARNING, "Bad L3 flags %x\n",
                 l3e_get_flags(l3e) & l3_disallow_mask(d));
        return -EINVAL;
    }

    rc = get_page_and_type_from_mfn(
        l3e_get_mfn(l3e), PGT_l2_page_table, d, partial, 1);
    if ( unlikely(rc == -EINVAL) &&
         !is_pv_32bit_domain(d) &&
         get_l3_linear_pagetable(l3e, pfn, d) )
        rc = 0;

    return rc;
}

/*
 * get_page_from_l4e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l4);
static int
get_page_from_l4e(
    l4_pgentry_t l4e, unsigned long pfn, struct domain *d, int partial)
{
    int rc;

    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l4e_get_flags(l4e) & L4_DISALLOW_MASK)) )
    {
        gdprintk(XENLOG_WARNING, "Bad L4 flags %x\n",
                 l4e_get_flags(l4e) & L4_DISALLOW_MASK);
        return -EINVAL;
    }

    rc = get_page_and_type_from_mfn(
        l4e_get_mfn(l4e), PGT_l3_page_table, d, partial, 1);
    if ( unlikely(rc == -EINVAL) && get_l4_linear_pagetable(l4e, pfn, d) )
        rc = 0;

    return rc;
}

/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static int put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) || (l2e_get_pfn(l2e) == pfn) )
        return 1;

    if ( l2e_get_flags(l2e) & _PAGE_PSE )
    {
        struct page_info *page = l2e_get_page(l2e);
        unsigned int i;

        for ( i = 0; i < (1u << PAGETABLE_ORDER); i++, page++ )
            put_page_and_type(page);
    }
    else
    {
        struct page_info *pg = l2e_get_page(l2e);
        int rc = put_page_type_ptpg(pg, mfn_to_page(_mfn(pfn)));

        ASSERT(!rc);
        put_page(pg);
    }

    return 0;
}

static int put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn,
                             int partial, bool defer)
{
    struct page_info *pg;
    int rc;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) || (l3e_get_pfn(l3e) == pfn) )
        return 1;

    if ( unlikely(l3e_get_flags(l3e) & _PAGE_PSE) )
    {
        unsigned long mfn = l3e_get_pfn(l3e);
        int writeable = l3e_get_flags(l3e) & _PAGE_RW;

        ASSERT(!(mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)));
        do {
            put_data_page(mfn_to_page(_mfn(mfn)), writeable);
        } while ( ++mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1) );

        return 0;
    }

    pg = l3e_get_page(l3e);

    if ( unlikely(partial > 0) )
    {
        ASSERT(!defer);
        return put_page_type_ptpg_preemptible(pg, mfn_to_page(_mfn(pfn)));
    }

    if ( defer )
    {
        current->arch.old_guest_ptpg = mfn_to_page(_mfn(pfn));
        current->arch.old_guest_table = pg;
        return 0;
    }

    rc = put_page_type_ptpg_preemptible(pg, mfn_to_page(_mfn(pfn)));
    if ( likely(!rc) )
        put_page(pg);

    return rc;
}

static int put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn,
                             int partial, bool defer)
{
    int rc = 1;

    if ( (l4e_get_flags(l4e) & _PAGE_PRESENT) &&
         (l4e_get_pfn(l4e) != pfn) )
    {
        struct page_info *pg = l4e_get_page(l4e);

        if ( unlikely(partial > 0) )
        {
            ASSERT(!defer);
            return put_page_type_ptpg_preemptible(pg, mfn_to_page(_mfn(pfn)));
        }

        if ( defer )
        {
            current->arch.old_guest_ptpg = mfn_to_page(_mfn(pfn));
            current->arch.old_guest_table = pg;
            return 0;
        }

        rc = put_page_type_ptpg_preemptible(pg, mfn_to_page(_mfn(pfn)));
        if ( likely(!rc) )
            put_page(pg);
    }

    return rc;
}

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
        struct page_info *page = NULL;

        if ( unlikely(l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom)) )
        {
            gdprintk(XENLOG_WARNING, "Bad L1 flags %x\n",
                    l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom));
            return -EINVAL;
        }

        /* Translate foreign guest address. */
        if ( paging_mode_translate(pg_dom) )
        {
            p2m_type_t p2mt;
            p2m_query_t q = l1e_get_flags(nl1e) & _PAGE_RW ?
                            P2M_ALLOC | P2M_UNSHARE : P2M_ALLOC;

            page = get_page_from_gfn(pg_dom, l1e_get_pfn(nl1e), &p2mt, q);

            if ( p2m_is_paged(p2mt) )
            {
                if ( page )
                    put_page(page);
                p2m_mem_paging_populate(pg_dom, l1e_get_pfn(nl1e));
                return -ENOENT;
            }

            if ( p2mt == p2m_ram_paging_in && !page )
                return -ENOENT;

            /* Did our attempt to unshare fail? */
            if ( (q & P2M_UNSHARE) && p2m_is_shared(p2mt) )
            {
                /* We could not have obtained a page ref. */
                ASSERT(!page);
                /* And mem_sharing_notify has already been called. */
                return -ENOMEM;
            }

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

        switch ( rc = get_page_from_l1e(nl1e, pt_dom, pg_dom,
                                        l1_disallow_mask(pt_dom)) )
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
static int mod_l2_entry(l2_pgentry_t *pl2e,
                        l2_pgentry_t nl2e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
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
static int mod_l3_entry(l3_pgentry_t *pl3e,
                        l3_pgentry_t nl3e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
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
static int mod_l4_entry(l4_pgentry_t *pl4e,
                        l4_pgentry_t nl4e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
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

static int alloc_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    l1_pgentry_t  *pl1e;
    unsigned int   i;
    int            ret = 0;

    pl1e = __map_domain_page(page);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        switch ( ret = get_page_from_l1e(pl1e[i], d, d, l1_disallow_mask(d)) )
        {
        default:
            goto fail;
        case 0:
            break;
        case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
            ASSERT(!(ret & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
            l1e_flip_flags(pl1e[i], ret);
            break;
        }

        pl1e[i] = adjust_guest_l1e(pl1e[i], d);
    }

    unmap_domain_page(pl1e);
    return 0;

 fail:
    gdprintk(XENLOG_WARNING, "Failure in alloc_l1_table: slot %#x\n", i);
    while ( i-- > 0 )
        put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
    return ret;
}

static int alloc_l2_table(struct page_info *page, unsigned long type,
                          int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = mfn_x(page_to_mfn(page));
    l2_pgentry_t  *pl2e;
    unsigned int   i;
    int            rc = 0;

    pl2e = map_domain_page(_mfn(pfn));

    for ( i = page->nr_validated_ptes; i < L2_PAGETABLE_ENTRIES; i++ )
    {
        if ( preemptible && i > page->nr_validated_ptes
             && hypercall_preempt_check() )
        {
            page->nr_validated_ptes = i;
            rc = -ERESTART;
            break;
        }

        if ( !is_guest_l2_slot(d, type, i) ||
             (rc = get_page_from_l2e(pl2e[i], pfn, d)) > 0 )
            continue;

        if ( rc < 0 )
        {
            gdprintk(XENLOG_WARNING, "Failure in alloc_l2_table: slot %#x\n", i);
            while ( i-- > 0 )
                if ( is_guest_l2_slot(d, type, i) )
                    put_page_from_l2e(pl2e[i], pfn);
            break;
        }

        pl2e[i] = adjust_guest_l2e(pl2e[i], d);
    }

    if ( rc >= 0 && (type & PGT_pae_xen_l2) )
        init_xen_pae_l2_slots(pl2e, d);

    unmap_domain_page(pl2e);
    return rc > 0 ? 0 : rc;
}

static int alloc_l3_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = mfn_x(page_to_mfn(page));
    l3_pgentry_t  *pl3e;
    unsigned int   i;
    int            rc = 0, partial = page->partial_pte;

    pl3e = map_domain_page(_mfn(pfn));

    /*
     * PAE guests allocate full pages, but aren't required to initialize
     * more than the first four entries; when running in compatibility
     * mode, however, the full page is visible to the MMU, and hence all
     * 512 entries must be valid/verified, which is most easily achieved
     * by clearing them out.
     */
    if ( is_pv_32bit_domain(d) )
        memset(pl3e + 4, 0, (L3_PAGETABLE_ENTRIES - 4) * sizeof(*pl3e));

    for ( i = page->nr_validated_ptes; i < L3_PAGETABLE_ENTRIES;
          i++, partial = 0 )
    {
        if ( is_pv_32bit_domain(d) && (i == 3) )
        {
            if ( !(l3e_get_flags(pl3e[i]) & _PAGE_PRESENT) ||
                 (l3e_get_flags(pl3e[i]) & l3_disallow_mask(d)) )
                rc = -EINVAL;
            else
                rc = get_page_and_type_from_mfn(
                    l3e_get_mfn(pl3e[i]),
                    PGT_l2_page_table | PGT_pae_xen_l2, d, partial, 1);
        }
        else if ( (rc = get_page_from_l3e(pl3e[i], pfn, d, partial)) > 0 )
            continue;

        if ( rc == -ERESTART )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = partial ?: 1;
        }
        else if ( rc == -EINTR && i )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = 0;
            rc = -ERESTART;
        }
        if ( rc < 0 )
            break;

        pl3e[i] = adjust_guest_l3e(pl3e[i], d);
    }

    if ( rc >= 0 && !create_pae_xen_mappings(d, pl3e) )
        rc = -EINVAL;
    if ( rc < 0 && rc != -ERESTART && rc != -EINTR )
    {
        gdprintk(XENLOG_WARNING, "Failure in alloc_l3_table: slot %#x\n", i);
        if ( i )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = 0;
            current->arch.old_guest_ptpg = NULL;
            current->arch.old_guest_table = page;
        }
        while ( i-- > 0 )
            pl3e[i] = unadjust_guest_l3e(pl3e[i], d);
    }

    unmap_domain_page(pl3e);
    return rc > 0 ? 0 : rc;
}

static int alloc_l4_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = mfn_x(page_to_mfn(page));
    l4_pgentry_t  *pl4e = map_domain_page(_mfn(pfn));
    unsigned int   i;
    int            rc = 0, partial = page->partial_pte;

    for ( i = page->nr_validated_ptes; i < L4_PAGETABLE_ENTRIES;
          i++, partial = 0 )
    {
        if ( !is_guest_l4_slot(d, i) ||
             (rc = get_page_from_l4e(pl4e[i], pfn, d, partial)) > 0 )
            continue;

        if ( rc == -ERESTART )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = partial ?: 1;
        }
        else if ( rc < 0 )
        {
            if ( rc != -EINTR )
                gdprintk(XENLOG_WARNING,
                         "Failure in alloc_l4_table: slot %#x\n", i);
            if ( i )
            {
                page->nr_validated_ptes = i;
                page->partial_pte = 0;
                if ( rc == -EINTR )
                    rc = -ERESTART;
                else
                {
                    if ( current->arch.old_guest_table )
                        page->nr_validated_ptes++;
                    current->arch.old_guest_ptpg = NULL;
                    current->arch.old_guest_table = page;
                }
            }
        }
        if ( rc < 0 )
        {
            unmap_domain_page(pl4e);
            return rc;
        }

        pl4e[i] = adjust_guest_l4e(pl4e[i], d);
    }

    if ( rc >= 0 )
    {
        init_xen_l4_slots(pl4e, _mfn(pfn),
                          d, INVALID_MFN, VM_ASSIST(d, m2p_strict));
        atomic_inc(&d->arch.pv_domain.nr_l4_pages);
        rc = 0;
    }
    unmap_domain_page(pl4e);

    return rc;
}

static void free_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    l1_pgentry_t *pl1e;
    unsigned int  i;

    pl1e = __map_domain_page(page);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
}


static int free_l2_table(struct page_info *page, int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l2_pgentry_t *pl2e;
    unsigned int  i = page->nr_validated_ptes - 1;
    int err = 0;

    pl2e = map_domain_page(_mfn(pfn));

    ASSERT(page->nr_validated_ptes);
    do {
        if ( is_guest_l2_slot(d, page->u.inuse.type_info, i) &&
             put_page_from_l2e(pl2e[i], pfn) == 0 &&
             preemptible && i && hypercall_preempt_check() )
        {
           page->nr_validated_ptes = i;
           err = -ERESTART;
        }
    } while ( !err && i-- );

    unmap_domain_page(pl2e);

    if ( !err )
        page->u.inuse.type_info &= ~PGT_pae_xen_l2;

    return err;
}

static int free_l3_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l3_pgentry_t *pl3e;
    int rc = 0, partial = page->partial_pte;
    unsigned int  i = page->nr_validated_ptes - !partial;

    pl3e = map_domain_page(_mfn(pfn));

    do {
        rc = put_page_from_l3e(pl3e[i], pfn, partial, 0);
        if ( rc < 0 )
            break;
        partial = 0;
        if ( rc > 0 )
            continue;
        pl3e[i] = unadjust_guest_l3e(pl3e[i], d);
    } while ( i-- );

    unmap_domain_page(pl3e);

    if ( rc == -ERESTART )
    {
        page->nr_validated_ptes = i;
        page->partial_pte = partial ?: -1;
    }
    else if ( rc == -EINTR && i < L3_PAGETABLE_ENTRIES - 1 )
    {
        page->nr_validated_ptes = i + 1;
        page->partial_pte = 0;
        rc = -ERESTART;
    }
    return rc > 0 ? 0 : rc;
}

static int free_l4_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l4_pgentry_t *pl4e = map_domain_page(_mfn(pfn));
    int rc = 0, partial = page->partial_pte;
    unsigned int  i = page->nr_validated_ptes - !partial;

    do {
        if ( is_guest_l4_slot(d, i) )
            rc = put_page_from_l4e(pl4e[i], pfn, partial, 0);
        if ( rc < 0 )
            break;
        partial = 0;
    } while ( i-- );

    if ( rc == -ERESTART )
    {
        page->nr_validated_ptes = i;
        page->partial_pte = partial ?: -1;
    }
    else if ( rc == -EINTR && i < L4_PAGETABLE_ENTRIES - 1 )
    {
        page->nr_validated_ptes = i + 1;
        page->partial_pte = 0;
        rc = -ERESTART;
    }

    unmap_domain_page(pl4e);

    if ( rc >= 0 )
    {
        atomic_dec(&d->arch.pv_domain.nr_l4_pages);
        rc = 0;
    }

    return rc;
}


void pv_dec_linear_pt(struct page_info *ptpg, struct page_info *page,
                      unsigned long type)
{
    if ( ptpg && PGT_type_equal(type, ptpg->u.inuse.type_info) )
    {
        ASSERT(is_pv_domain(page_get_owner(page)));
        ASSERT(is_pv_domain(page_get_owner(ptpg)));

        dec_linear_uses(page);
        dec_linear_entries(ptpg);
    }
}

/*
 * Special version of get_page() to be used exclusively when
 * - a page is known to already have a non-zero reference count
 * - the page does not need its owner to be checked
 * - it will not be called more than once without dropping the thus
 *   acquired reference again.
 * Due to get_page() reserving one reference, this call cannot fail.
 */
static void get_page_light(struct page_info *page)
{
    unsigned long x, nx, y = page->count_info;

    do {
        x  = y;
        nx = x + 1;
        BUG_ON(!(x & PGC_count_mask)); /* Not allocated? */
        BUG_ON(!(nx & PGC_count_mask)); /* Overflow? */
        y = cmpxchg(&page->count_info, x, nx);
    }
    while ( unlikely(y != x) );
}

int pv_put_final_page_type(struct page_info *page, unsigned long type,
                           bool preemptible, struct page_info *ptpg)
{
    int rc = pv_free_page_type(page, type, preemptible);

    /* No need for atomic update of type_info here: noone else updates it. */
    if ( rc == 0 )
    {
        pv_dec_linear_pt(ptpg, page, type);
        ASSERT(!page->linear_pt_count || page_get_owner(page)->is_dying);
        set_tlbflush_timestamp(page);
        smp_wmb();
        page->u.inuse.type_info--;
    }
    else if ( rc == -EINTR )
    {
        ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
        smp_wmb();
        page->u.inuse.type_info |= PGT_validated;
    }
    else
    {
        BUG_ON(rc != -ERESTART);
        smp_wmb();
        get_page_light(page);
        page->u.inuse.type_info |= PGT_partial;
    }

    return rc;
}

static int alloc_segdesc_page(struct page_info *page)
{
    const struct domain *owner = page_get_owner(page);
    struct desc_struct *descs = __map_domain_page(page);
    unsigned i;

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(owner, &descs[i])) )
            break;

    unmap_domain_page(descs);

    return i == 512 ? 0 : -EINVAL;
}

int pv_alloc_page_type(struct page_info *page, unsigned long type,
                       bool preemptible)
{
    struct domain *owner = page_get_owner(page);
    int rc;

    /* A page table is dirtied when its type count becomes non-zero. */
    if ( likely(owner != NULL) )
        paging_mark_dirty(owner, page_to_mfn(page));

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        rc = alloc_l1_table(page);
        break;
    case PGT_l2_page_table:
        rc = alloc_l2_table(page, type, preemptible);
        break;
    case PGT_l3_page_table:
        ASSERT(preemptible);
        rc = alloc_l3_table(page);
        break;
    case PGT_l4_page_table:
        ASSERT(preemptible);
        rc = alloc_l4_table(page);
        break;
    case PGT_seg_desc_page:
        rc = alloc_segdesc_page(page);
        break;
    default:
        printk("Bad type in %s %lx t=%" PRtype_info " c=%lx\n", __func__,
               type, page->u.inuse.type_info,
               page->count_info);
        rc = -EINVAL;
        BUG();
    }

    /* No need for atomic update of type_info here: noone else updates it. */
    smp_wmb();
    switch ( rc )
    {
    case 0:
        page->u.inuse.type_info |= PGT_validated;
        break;
    case -EINTR:
        ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
        page->u.inuse.type_info &= ~PGT_count_mask;
        break;
    default:
        ASSERT(rc < 0);
        gdprintk(XENLOG_WARNING, "Error while validating mfn %" PRI_mfn
                 " (pfn %" PRI_pfn ") for type %" PRtype_info
                 ": caf=%08lx taf=%" PRtype_info "\n",
                 mfn_x(page_to_mfn(page)),
                 get_gpfn_from_mfn(mfn_x(page_to_mfn(page))),
                 type, page->count_info, page->u.inuse.type_info);
        if ( page != current->arch.old_guest_table )
            page->u.inuse.type_info = 0;
        else
        {
            ASSERT((page->u.inuse.type_info &
                    (PGT_count_mask | PGT_validated)) == 1);
    case -ERESTART:
            get_page_light(page);
            page->u.inuse.type_info |= PGT_partial;
        }
        break;
    }

    return rc;
}


int pv_free_page_type(struct page_info *page, unsigned long type,
                      bool preemptible)
{
    struct domain *owner = page_get_owner(page);
    unsigned long gmfn;
    int rc;

    if ( likely(owner != NULL) && unlikely(paging_mode_enabled(owner)) )
    {
        /* A page table is dirtied when its type count becomes zero. */
        paging_mark_dirty(owner, page_to_mfn(page));

        ASSERT(!shadow_mode_refcounts(owner));

        gmfn = mfn_to_gmfn(owner, mfn_x(page_to_mfn(page)));
        ASSERT(VALID_M2P(gmfn));
        /* Page sharing not supported for shadowed domains */
        if(!SHARED_M2P(gmfn))
            shadow_remove_all_shadows(owner, _mfn(gmfn));
    }

    if ( !(type & PGT_partial) )
    {
        page->nr_validated_ptes = 1U << PAGETABLE_ORDER;
        page->partial_pte = 0;
    }

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        free_l1_table(page);
        rc = 0;
        break;
    case PGT_l2_page_table:
        rc = free_l2_table(page, preemptible);
        break;
    case PGT_l3_page_table:
        ASSERT(preemptible);
        rc = free_l3_table(page);
        break;
    case PGT_l4_page_table:
        ASSERT(preemptible);
        rc = free_l4_table(page);
        break;
    default:
        gdprintk(XENLOG_WARNING, "type %" PRtype_info " mfn %" PRI_mfn "\n",
                 type, mfn_x(page_to_mfn(page)));
        rc = -EINVAL;
        BUG();
    }

    return rc;
}

int new_guest_cr3(mfn_t mfn)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    int rc;
    mfn_t old_base_mfn;

    if ( is_pv_32bit_domain(d) )
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

        pv_destroy_ldt(curr); /* Unconditional TLB flush later. */
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

    rc = get_page_and_type_from_mfn(mfn, PGT_root_page_table, d, 0, 1);
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

    pv_destroy_ldt(curr); /* Unconditional TLB flush later. */

    if ( !VM_ASSIST(d, m2p_strict) && !paging_mode_refcounts(d) )
        fill_ro_mpt(mfn);
    curr->arch.guest_table = pagetable_from_mfn(mfn);
    update_cr3(curr);

    write_ptbase(curr);

    if ( likely(mfn_x(old_base_mfn) != 0) )
    {
        struct page_info *page = mfn_to_page(old_base_mfn);

        if ( paging_mode_refcounts(d) )
            put_page(page);
        else
            switch ( rc = put_page_and_type_preemptible(page) )
            {
            case -EINTR:
                rc = -ERESTART;
                /* fallthrough */
            case -ERESTART:
                curr->arch.old_guest_ptpg = NULL;
                curr->arch.old_guest_table = page;
                break;
            default:
                BUG_ON(rc);
                break;
            }
    }

    return rc;
}

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
            if ( ((v = d->vcpu[vcpu_id]) != NULL) && vcpu_cpu_dirty(v) )
                __cpumask_set_cpu(v->dirty_cpu, pmask);
        }
    }
}

long do_mmuext_op(
    XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom)
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
                    {
                        curr->arch.old_guest_ptpg = NULL;
                        curr->arch.old_guest_table = page;
                    }
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
                curr->arch.old_guest_ptpg = NULL;
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
                    curr->arch.old_guest_ptpg = NULL;
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
                flush_tlb_mask(currd->dirty_cpumask);
            else
                rc = -EPERM;
            break;

        case MMUEXT_INVLPG_ALL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( __addr_ok(op.arg1.linear_addr) )
                flush_tlb_one_mask(currd->dirty_cpumask, op.arg1.linear_addr);
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
                if ( pv_destroy_ldt(curr) )
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

long do_mmu_update(
    XEN_GUEST_HANDLE_PARAM(mmu_update_t) ureqs,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
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
    bool sync_guest = false;
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

            if ( unlikely(!page) || p2mt != p2m_ram_rw )
            {
                if ( page )
                    put_page(page);
                if ( p2m_is_paged(p2mt) )
                {
                    p2m_mem_paging_populate(pt_owner, gmfn);
                    rc = -ENOENT;
                }
                else
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
                    rc = mod_l1_entry(va, l1e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v,
                                      pg_owner);
                    break;

                case PGT_l2_page_table:
                    if ( unlikely(pg_owner != pt_owner) )
                        break;
                    rc = mod_l2_entry(va, l2e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    break;

                case PGT_l3_page_table:
                    if ( unlikely(pg_owner != pt_owner) )
                        break;
                    rc = mod_l3_entry(va, l3e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    break;

                case PGT_l4_page_table:
                    if ( unlikely(pg_owner != pt_owner) )
                        break;
                    rc = mod_l4_entry(va, l4e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    /*
                     * No need to sync if all uses of the page can be accounted
                     * to the page lock we hold, its pinned status, and uses on
                     * this (v)CPU.
                     */
                    if ( !rc && this_cpu(root_pgt) &&
                         ((page->u.inuse.type_info & PGT_count_mask) >
                          (1 + !!(page->u.inuse.type_info & PGT_pinned) +
                           (pagetable_get_pfn(curr->arch.guest_table) == mfn) +
                           (pagetable_get_pfn(curr->arch.guest_table_user) ==
                            mfn))) )
                        sync_guest = true;
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

            page = get_page_from_mfn(_mfn(mfn), pg_owner);
            if ( unlikely(!page) )
            {
                gdprintk(XENLOG_WARNING,
                         "Could not get page for mach->phys update\n");
                rc = -EINVAL;
                break;
            }

            set_gpfn_from_mfn(mfn, gpfn);

            paging_mark_dirty(pg_owner, _mfn(mfn));

            put_page(page);
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

    if ( sync_guest )
    {
        /*
         * Force other vCPU-s of the affected guest to pick up L4 entry
         * changes (if any). Issue a flush IPI with empty operation mask to
         * facilitate this (including ourselves waiting for the IPI to
         * actually have arrived). Utilize the fact that FLUSH_VA_VALID is
         * meaningless without FLUSH_CACHE, but will allow to pass the no-op
         * check in flush_area_mask().
         */
        unsigned int cpu = smp_processor_id();
        cpumask_t *mask = per_cpu(scratch_cpumask, cpu);

        cpumask_andnot(mask, pt_owner->dirty_cpumask, cpumask_of(cpu));
        if ( !cpumask_empty(mask) )
            flush_area_mask(mask, ZERO_BLOCK_PTR, FLUSH_VA_VALID);
    }

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

static int __do_update_va_mapping(
    unsigned long va, u64 val64, unsigned long flags, struct domain *pg_owner)
{
    l1_pgentry_t   val = l1e_from_intpte(val64);
    struct vcpu   *v   = current;
    struct domain *d   = v->domain;
    struct page_info *gl1pg;
    l1_pgentry_t  *pl1e;
    unsigned long  bmap_ptr;
    mfn_t          gl1mfn;
    cpumask_t     *mask = NULL;
    int            rc;

    perfc_incr(calls_to_update_va);

    rc = xsm_update_va_mapping(XSM_TARGET, d, pg_owner, val);
    if ( rc )
        return rc;

    rc = -EINVAL;
    pl1e = map_guest_l1e(va, &gl1mfn);
    gl1pg = pl1e ? get_page_from_mfn(gl1mfn, d) : NULL;
    if ( unlikely(!gl1pg) )
        goto out;

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

    rc = mod_l1_entry(pl1e, val, mfn_x(gl1mfn), 0, v, pg_owner);

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
            mask = d->dirty_cpumask;
            break;
        default:
            mask = this_cpu(scratch_cpumask);
            rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void),
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
            paging_invlpg(v, va);
            break;
        case UVMF_ALL:
            mask = d->dirty_cpumask;
            break;
        default:
            mask = this_cpu(scratch_cpumask);
            rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void),
                                      mask);
            break;
        }
        if ( mask )
            flush_tlb_one_mask(mask, va);
        break;
    }

    return rc;
}

long do_update_va_mapping(unsigned long va, u64 val64,
                          unsigned long flags)
{
    return __do_update_va_mapping(va, val64, flags, current->domain);
}

long do_update_va_mapping_otherdomain(unsigned long va, u64 val64,
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
