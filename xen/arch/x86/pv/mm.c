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

#include <xen/event.h>
#include <xen/guest_access.h>

#include <asm/current.h>
#include <asm/mm.h>
#include <asm/p2m.h>
#include <asm/setup.h>
#include <asm/shadow.h>

#include "mm.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

#ifndef NDEBUG
static unsigned int __read_mostly root_pgt_pv_xen_slots
    = ROOT_PAGETABLE_PV_XEN_SLOTS;
static l4_pgentry_t __read_mostly split_l4e;
#else
#define root_pgt_pv_xen_slots ROOT_PAGETABLE_PV_XEN_SLOTS
#endif

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
#define define_get_linear_pagetable(level)                                  \
static int                                                                  \
get_##level##_linear_pagetable(                                             \
    level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d)         \
{                                                                           \
    unsigned long x, y;                                                     \
    struct page_info *page;                                                 \
    unsigned long pfn;                                                      \
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
        /* Make sure the mapped frame belongs to the correct domain. */     \
        if ( unlikely(!get_page_from_mfn(_mfn(pfn), d)) )                   \
            return 0;                                                       \
                                                                            \
        /*                                                                  \
         * Ensure that the mapped frame is an already-validated page table. \
         * If so, atomically increment the count (checking for overflow).   \
         */                                                                 \
        page = mfn_to_page(_mfn(pfn));                                      \
        y = page->u.inuse.type_info;                                        \
        do {                                                                \
            x = y;                                                          \
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||        \
                 unlikely((x & (PGT_type_mask|PGT_validated)) !=            \
                          (PGT_##level##_page_table|PGT_validated)) )       \
            {                                                               \
                put_page(page);                                             \
                return 0;                                                   \
            }                                                               \
        }                                                                   \
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );   \
    }                                                                       \
                                                                            \
    return 1;                                                               \
}

int get_page_and_type_from_mfn(mfn_t mfn, unsigned long type, struct domain *d,
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

/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
/*
 * get_page_from_l2e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l2);
int get_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn, struct domain *d)
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

    if ( !(l2e_get_flags(l2e) & _PAGE_PSE) )
    {
        rc = get_page_and_type_from_mfn(_mfn(mfn), PGT_l1_page_table, d, 0, 0);
        if ( unlikely(rc == -EINVAL) && get_l2_linear_pagetable(l2e, pfn, d) )
            rc = 0;
        return rc;
    }

    return -EINVAL;
}


/*
 * get_page_from_l3e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l3);
int get_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn, struct domain *d,
                      int partial)
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
int get_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn, struct domain *d,
                      int partial)
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
int put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) || (l2e_get_pfn(l2e) == pfn) )
        return 1;

    if ( l2e_get_flags(l2e) & _PAGE_PSE )
    {
        struct page_info *page = l2e_get_page(l2e);
        unsigned int i;

        for ( i = 0; i < (1u << PAGETABLE_ORDER); i++, page++ )
            put_page_and_type(page);
    } else
        put_page_and_type(l2e_get_page(l2e));

    return 0;
}

static void put_data_page(struct page_info *page, bool writeable)
{
    if ( writeable )
        put_page_and_type(page);
    else
        put_page(page);
}

int put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn, int partial,
                      bool defer)
{
    struct page_info *pg;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) || (l3e_get_pfn(l3e) == pfn) )
        return 1;

    if ( unlikely(l3e_get_flags(l3e) & _PAGE_PSE) )
    {
        unsigned long mfn = l3e_get_pfn(l3e);
        bool writeable = l3e_get_flags(l3e) & _PAGE_RW;

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
        return put_page_type_preemptible(pg);
    }

    if ( defer )
    {
        current->arch.old_guest_table = pg;
        return 0;
    }

    return put_page_and_type_preemptible(pg);
}

int put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn, int partial,
                      bool defer)
{
    if ( (l4e_get_flags(l4e) & _PAGE_PRESENT) &&
         (l4e_get_pfn(l4e) != pfn) )
    {
        struct page_info *pg = l4e_get_page(l4e);

        if ( unlikely(partial > 0) )
        {
            ASSERT(!defer);
            return put_page_type_preemptible(pg);
        }

        if ( defer )
        {
            current->arch.old_guest_table = pg;
            return 0;
        }

        return put_page_and_type_preemptible(pg);
    }
    return 1;
}

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
        toggle_guest_mode(curr);

    l1e = guest_get_eff_l1e(linear);

    if ( user_mode )
        toggle_guest_mode(curr);

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
 * This function must write all ROOT_PAGETABLE_PV_XEN_SLOTS, to clobber any
 * values a guest may have left there from alloc_l4_table().
 */
void init_guest_l4_table(l4_pgentry_t l4tab[], const struct domain *d,
                         bool zap_ro_mpt)
{
    /* Xen private mappings. */
    memcpy(&l4tab[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           root_pgt_pv_xen_slots * sizeof(l4_pgentry_t));
#ifndef NDEBUG
    if ( unlikely(root_pgt_pv_xen_slots < ROOT_PAGETABLE_PV_XEN_SLOTS) )
    {
        l4_pgentry_t *next = &l4tab[ROOT_PAGETABLE_FIRST_XEN_SLOT +
                                    root_pgt_pv_xen_slots];

        if ( l4e_get_intpte(split_l4e) )
            *next++ = split_l4e;

        memset(next, 0,
               _p(&l4tab[ROOT_PAGETABLE_LAST_XEN_SLOT + 1]) - _p(next));
    }
#else
    BUILD_BUG_ON(root_pgt_pv_xen_slots != ROOT_PAGETABLE_PV_XEN_SLOTS);
#endif
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_pfn(domain_page_map_to_mfn(l4tab), __PAGE_HYPERVISOR_RW);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_page(d->arch.perdomain_l3_pg, __PAGE_HYPERVISOR_RW);
    if ( zap_ro_mpt || is_pv_32bit_domain(d) )
        l4tab[l4_table_offset(RO_MPT_VIRT_START)] = l4e_empty();
}

void pv_arch_init_memory(void)
{
#ifndef NDEBUG
    unsigned int i;

    if ( highmem_start )
    {
        unsigned long split_va = (unsigned long)__va(highmem_start);

        if ( split_va < HYPERVISOR_VIRT_END &&
             split_va - 1 == (unsigned long)__va(highmem_start - 1) )
        {
            root_pgt_pv_xen_slots = l4_table_offset(split_va) -
                                    ROOT_PAGETABLE_FIRST_XEN_SLOT;
            ASSERT(root_pgt_pv_xen_slots < ROOT_PAGETABLE_PV_XEN_SLOTS);
            if ( l4_table_offset(split_va) == l4_table_offset(split_va - 1) )
            {
                l3_pgentry_t *l3tab = alloc_xen_pagetable();

                if ( l3tab )
                {
                    const l3_pgentry_t *l3idle =
                        l4e_to_l3e(idle_pg_table[l4_table_offset(split_va)]);

                    for ( i = 0; i < l3_table_offset(split_va); ++i )
                        l3tab[i] = l3idle[i];
                    for ( ; i < L3_PAGETABLE_ENTRIES; ++i )
                        l3tab[i] = l3e_empty();
                    split_l4e = l4e_from_pfn(virt_to_mfn(l3tab),
                                             __PAGE_HYPERVISOR_RW);
                }
                else
                    ++root_pgt_pv_xen_slots;
            }
        }
    }
#endif
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

static int alloc_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    l1_pgentry_t  *pl1e;
    unsigned int   i;
    int            ret = 0;

    pl1e = __map_domain_page(page);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        switch ( ret = get_page_from_l1e(pl1e[i], d, d) )
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

int create_pae_xen_mappings(struct domain *d, l3_pgentry_t *pl3e)
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
    {
        /* Xen private mappings. */
        memcpy(&pl2e[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
               &compat_idle_pg_table_l2[
                   l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
               COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*pl2e));
    }

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
        init_guest_l4_table(pl4e, d, !VM_ASSIST(d, m2p_strict));
        atomic_inc(&d->arch.pv_domain.nr_l4_pages);
        rc = 0;
    }
    unmap_domain_page(pl4e);

    return rc;
}

int pv_alloc_page_type(struct page_info *page, unsigned long type,
                       int preemptible)
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

int pv_free_page_type(struct page_info *page, unsigned long type,
                      int preemptible)
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

void pv_invalidate_shadow_ldt(struct vcpu *v, bool flush)
{
    l1_pgentry_t *pl1e;
    unsigned int i;
    struct page_info *page;

    BUG_ON(unlikely(in_irq()));

    spin_lock(&v->arch.pv_vcpu.shadow_ldt_lock);

    if ( v->arch.pv_vcpu.shadow_ldt_mapcnt == 0 )
        goto out;

    v->arch.pv_vcpu.shadow_ldt_mapcnt = 0;
    pl1e = pv_ldt_ptes(v);

    for ( i = 0; i < 16; i++ )
    {
        if ( !(l1e_get_flags(pl1e[i]) & _PAGE_PRESENT) )
            continue;
        page = l1e_get_page(pl1e[i]);
        l1e_write(&pl1e[i], l1e_empty());
        ASSERT_PAGE_IS_TYPE(page, PGT_seg_desc_page);
        ASSERT_PAGE_IS_DOMAIN(page, v->domain);
        put_page_and_type(page);
    }

    /* Rid TLBs of stale mappings (guest mappings and shadow mappings). */
    if ( flush )
        flush_tlb_mask(v->vcpu_dirty_cpumask);

 out:
    spin_unlock(&v->arch.pv_vcpu.shadow_ldt_lock);
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
