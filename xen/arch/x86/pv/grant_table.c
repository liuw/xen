/******************************************************************************
 * arch/x86/pv/grant_table.c
 *
 * Grant table interfaces for PV guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
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

#include <xen/types.h>

#include <public/grant_table.h>

#include <asm/p2m.h>
#include <asm/pv/mm.h>

static int create_grant_pte_mapping(uint64_t pte_addr, l1_pgentry_t nl1e,
                                    struct vcpu *v)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gmfn, mfn;
    struct page_info *page;
    l1_pgentry_t ol1e;
    struct domain *d = v->domain;

    adjust_guest_l1e(nl1e, d);

    gmfn = pte_addr >> PAGE_SHIFT;
    page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);

    if ( unlikely(!page) )
    {
        gdprintk(XENLOG_WARNING, "Could not get page for normal update\n");
        return GNTST_general_error;
    }

    mfn = page_to_mfn(page);
    va = map_domain_page(_mfn(mfn));
    va = (void *)((unsigned long)va + ((unsigned long)pte_addr & ~PAGE_MASK));

    if ( !page_lock(page) )
    {
        rc = GNTST_general_error;
        goto failed;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        rc = GNTST_general_error;
        goto failed;
    }

    ol1e = *(l1_pgentry_t *)va;
    if ( !UPDATE_ENTRY(l1, (l1_pgentry_t *)va, ol1e, nl1e, mfn, v, 0) )
    {
        page_unlock(page);
        rc = GNTST_general_error;
        goto failed;
    }

    page_unlock(page);

    put_page_from_l1e(ol1e, d);

 failed:
    unmap_domain_page(va);
    put_page(page);

    return rc;
}

static int destroy_grant_pte_mapping(uint64_t addr, unsigned long frame,
                                     struct domain *d)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gmfn, mfn;
    struct page_info *page;
    l1_pgentry_t ol1e;

    gmfn = addr >> PAGE_SHIFT;
    page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);

    if ( unlikely(!page) )
    {
        gdprintk(XENLOG_WARNING, "Could not get page for normal update\n");
        return GNTST_general_error;
    }

    mfn = page_to_mfn(page);
    va = map_domain_page(_mfn(mfn));
    va = (void *)((unsigned long)va + ((unsigned long)addr & ~PAGE_MASK));

    if ( !page_lock(page) )
    {
        rc = GNTST_general_error;
        goto failed;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        rc = GNTST_general_error;
        goto failed;
    }

    ol1e = *(l1_pgentry_t *)va;

    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        page_unlock(page);
        gdprintk(XENLOG_WARNING,
                 "PTE entry %"PRIpte" for address %"PRIx64" doesn't match frame %lx\n",
                 l1e_get_intpte(ol1e), addr, frame);
        rc = GNTST_general_error;
        goto failed;
    }

    /* Delete pagetable entry. */
    if ( unlikely(!UPDATE_ENTRY(l1,
                                (l1_pgentry_t *)va, ol1e, l1e_empty(), mfn,
                                d->vcpu[0] /* Change if we go to per-vcpu shadows. */,
                                0)) )
    {
        page_unlock(page);
        gdprintk(XENLOG_WARNING, "Cannot delete PTE entry at %p\n", va);
        rc = GNTST_general_error;
        goto failed;
    }

    page_unlock(page);

 failed:
    unmap_domain_page(va);
    put_page(page);
    return rc;
}


static int create_grant_va_mapping(unsigned long va, l1_pgentry_t nl1e,
                                   struct vcpu *v)
{
    l1_pgentry_t *pl1e, ol1e;
    struct domain *d = v->domain;
    unsigned long gl1mfn;
    struct page_info *l1pg;
    int okay;

    adjust_guest_l1e(nl1e, d);

    pl1e = pv_map_guest_l1e(va, &gl1mfn);
    if ( !pl1e )
    {
        gdprintk(XENLOG_WARNING, "Could not find L1 PTE for address %lx\n", va);
        return GNTST_general_error;
    }

    if ( get_page_from_pagenr(gl1mfn, current->domain) )
    {
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    l1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(l1pg) )
    {
        put_page(l1pg);
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    if ( (l1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(l1pg);
        put_page(l1pg);
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    ol1e = *pl1e;
    okay = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, v, 0);

    page_unlock(l1pg);
    put_page(l1pg);
    pv_unmap_guest_l1e(pl1e);

    if ( okay )
        put_page_from_l1e(ol1e, d);

    return okay ? GNTST_okay : GNTST_general_error;
}

static int replace_grant_va_mapping(unsigned long addr, unsigned long frame,
                                    l1_pgentry_t nl1e, struct vcpu *v)
{
    l1_pgentry_t *pl1e, ol1e;
    unsigned long gl1mfn;
    struct page_info *l1pg;
    int rc = 0;

    pl1e = pv_map_guest_l1e(addr, &gl1mfn);
    if ( !pl1e )
    {
        gdprintk(XENLOG_WARNING, "Could not find L1 PTE for address %lx\n", addr);
        return GNTST_general_error;
    }

    if ( get_page_from_pagenr(gl1mfn, current->domain) )
    {
        rc = GNTST_general_error;
        goto out;
    }

    l1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(l1pg) )
    {
        rc = GNTST_general_error;
        put_page(l1pg);
        goto out;
    }

    if ( (l1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        rc = GNTST_general_error;
        goto unlock_and_out;
    }

    ol1e = *pl1e;

    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        gdprintk(XENLOG_WARNING,
                 "PTE entry %lx for address %lx doesn't match frame %lx\n",
                 l1e_get_pfn(ol1e), addr, frame);
        rc = GNTST_general_error;
        goto unlock_and_out;
    }

    /* Delete pagetable entry. */
    if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, v, 0)) )
    {
        gdprintk(XENLOG_WARNING, "Cannot delete PTE entry at %p\n", pl1e);
        rc = GNTST_general_error;
        goto unlock_and_out;
    }

 unlock_and_out:
    page_unlock(l1pg);
    put_page(l1pg);
 out:
    pv_unmap_guest_l1e(pl1e);
    return rc;
}

static int destroy_grant_va_mapping(unsigned long addr, unsigned long frame,
                                    struct vcpu *v)
{
    return replace_grant_va_mapping(addr, frame, l1e_empty(), v);
}

int create_grant_pv_mapping(uint64_t addr, unsigned long frame,
                            unsigned int flags, unsigned int cache_flags)
{
    l1_pgentry_t pte;
    uint32_t grant_pte_flags;

    grant_pte_flags =
        _PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_GNTTAB;
    if ( cpu_has_nx )
        grant_pte_flags |= _PAGE_NX_BIT;

    pte = l1e_from_pfn(frame, grant_pte_flags);
    if ( (flags & GNTMAP_application_map) )
        l1e_add_flags(pte,_PAGE_USER);
    if ( !(flags & GNTMAP_readonly) )
        l1e_add_flags(pte,_PAGE_RW);

    l1e_add_flags(pte,
                  ((flags >> _GNTMAP_guest_avail0) * _PAGE_AVAIL0)
                   & _PAGE_AVAIL);

    l1e_add_flags(pte, cacheattr_to_pte_flags(cache_flags >> 5));

    if ( flags & GNTMAP_contains_pte )
        return create_grant_pte_mapping(addr, pte, current);
    return create_grant_va_mapping(addr, pte, current);
}

int replace_grant_pv_mapping(uint64_t addr, unsigned long frame,
                             uint64_t new_addr, unsigned int flags)
{
    struct vcpu *curr = current;
    l1_pgentry_t *pl1e, ol1e;
    unsigned long gl1mfn;
    struct page_info *l1pg;
    int rc;

    if ( flags & GNTMAP_contains_pte )
    {
        if ( !new_addr )
            return destroy_grant_pte_mapping(addr, frame, curr->domain);

        return GNTST_general_error;
    }

    if ( !new_addr )
        return destroy_grant_va_mapping(addr, frame, curr);

    pl1e = pv_map_guest_l1e(new_addr, &gl1mfn);
    if ( !pl1e )
    {
        gdprintk(XENLOG_WARNING,
                 "Could not find L1 PTE for address %"PRIx64"\n", new_addr);
        return GNTST_general_error;
    }

    if ( get_page_from_pagenr(gl1mfn, current->domain) )
    {
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    l1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(l1pg) )
    {
        put_page(l1pg);
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    if ( (l1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(l1pg);
        put_page(l1pg);
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    ol1e = *pl1e;

    if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, l1e_empty(),
                                gl1mfn, curr, 0)) )
    {
        page_unlock(l1pg);
        put_page(l1pg);
        gdprintk(XENLOG_WARNING, "Cannot delete PTE entry at %p\n", pl1e);
        pv_unmap_guest_l1e(pl1e);
        return GNTST_general_error;
    }

    page_unlock(l1pg);
    put_page(l1pg);
    pv_unmap_guest_l1e(pl1e);

    rc = replace_grant_va_mapping(addr, frame, ol1e, curr);
    if ( rc )
        put_page_from_l1e(ol1e, curr->domain);

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
