/******************************************************************************
 * arch/x86/pv/descriptor-tables.c
 *
 * Descriptor table related code
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

#include <xen/guest_access.h>
#include <xen/hypercall.h>

#include <asm/p2m.h>
#include <asm/pv/mm.h>
#include <asm/pv/processor.h>

/*************************
 * Descriptor Tables
 */

void pv_destroy_gdt(struct vcpu *v)
{
    l1_pgentry_t *pl1e;
    unsigned int i;
    unsigned long pfn, zero_pfn = PFN_DOWN(__pa(zero_page));

    v->arch.pv_vcpu.gdt_ents = 0;
    pl1e = gdt_ldt_ptes(v->domain, v);
    for ( i = 0; i < FIRST_RESERVED_GDT_PAGE; i++ )
    {
        pfn = l1e_get_pfn(pl1e[i]);
        if ( (l1e_get_flags(pl1e[i]) & _PAGE_PRESENT) && pfn != zero_pfn )
            put_page_and_type(mfn_to_page(pfn));
        l1e_write(&pl1e[i], l1e_from_pfn(zero_pfn, __PAGE_HYPERVISOR_RO));
        v->arch.pv_vcpu.gdt_frames[i] = 0;
    }
}

long pv_set_gdt(struct vcpu *v, unsigned long *frames, unsigned int entries)
{
    struct domain *d = v->domain;
    l1_pgentry_t *pl1e;
    /* NB. There are 512 8-byte entries per GDT page. */
    unsigned int i, nr_pages = (entries + 511) / 512;

    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    /* Check the pages in the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
    {
        struct page_info *page;

        page = get_page_from_gfn(d, frames[i], NULL, P2M_ALLOC);
        if ( !page )
            goto fail;
        if ( !get_page_type(page, PGT_seg_desc_page) )
        {
            put_page(page);
            goto fail;
        }
        frames[i] = page_to_mfn(page);
    }

    /* Tear down the old GDT. */
    pv_destroy_gdt(v);

    /* Install the new GDT. */
    v->arch.pv_vcpu.gdt_ents = entries;
    pl1e = gdt_ldt_ptes(d, v);
    for ( i = 0; i < nr_pages; i++ )
    {
        v->arch.pv_vcpu.gdt_frames[i] = frames[i];
        l1e_write(&pl1e[i], l1e_from_pfn(frames[i], __PAGE_HYPERVISOR_RW));
    }

    return 0;

 fail:
    while ( i-- > 0 )
    {
        put_page_and_type(mfn_to_page(frames[i]));
    }
    return -EINVAL;
}


long do_set_gdt(XEN_GUEST_HANDLE_PARAM(xen_ulong_t) frame_list,
                unsigned int entries)
{
    int nr_pages = (entries + 511) / 512;
    unsigned long frames[16];
    struct vcpu *curr = current;
    long ret;

    /* Rechecked in pv_set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    if ( copy_from_guest(frames, frame_list, nr_pages) )
        return -EFAULT;

    domain_lock(curr->domain);

    if ( (ret = pv_set_gdt(curr, frames, entries)) == 0 )
        flush_tlb_local();

    domain_unlock(curr->domain);

    return ret;
}

long do_update_descriptor(u64 pa, u64 desc)
{
    struct domain *dom = current->domain;
    unsigned long gmfn = pa >> PAGE_SHIFT;
    unsigned long mfn;
    unsigned int  offset;
    struct desc_struct *gdt_pent, d;
    struct page_info *page;
    long ret = -EINVAL;

    offset = ((unsigned int)pa & ~PAGE_MASK) / sizeof(struct desc_struct);

    *(u64 *)&d = desc;

    page = get_page_from_gfn(dom, gmfn, NULL, P2M_ALLOC);
    if ( (((unsigned int)pa % sizeof(struct desc_struct)) != 0) ||
         !page ||
         !check_descriptor(dom, &d) )
    {
        if ( page )
            put_page(page);
        return -EINVAL;
    }
    mfn = page_to_mfn(page);

    /* Check if the given frame is in use in an unsafe context. */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_seg_desc_page:
        if ( unlikely(!get_page_type(page, PGT_seg_desc_page)) )
            goto out;
        break;
    default:
        if ( unlikely(!get_page_type(page, PGT_writable_page)) )
            goto out;
        break;
    }

    paging_mark_dirty(dom, _mfn(mfn));

    /* All is good so make the update. */
    gdt_pent = map_domain_page(_mfn(mfn));
    write_atomic((uint64_t *)&gdt_pent[offset], *(uint64_t *)&d);
    unmap_domain_page(gdt_pent);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    return ret;
}

int compat_set_gdt(XEN_GUEST_HANDLE_PARAM(uint) frame_list,
                   unsigned int entries)
{
    unsigned int i, nr_pages = (entries + 511) / 512;
    unsigned long frames[16];
    long ret;

    /* Rechecked in pv_set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    if ( !guest_handle_okay(frame_list, nr_pages) )
        return -EFAULT;

    for ( i = 0; i < nr_pages; ++i )
    {
        unsigned int frame;

        if ( __copy_from_guest(&frame, frame_list, 1) )
            return -EFAULT;
        frames[i] = frame;
        guest_handle_add_offset(frame_list, 1);
    }

    domain_lock(current->domain);

    if ( (ret = pv_set_gdt(current, frames, entries)) == 0 )
        flush_tlb_local();

    domain_unlock(current->domain);

    return ret;
}

int compat_update_descriptor(u32 pa_lo, u32 pa_hi, u32 desc_lo, u32 desc_hi)
{
    return do_update_descriptor(pa_lo | ((u64)pa_hi << 32),
                                desc_lo | ((u64)desc_hi << 32));
}

/* Map shadow page at offset @off. */
bool pv_map_ldt_shadow_page(unsigned int off)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    unsigned long gmfn;
    struct page_info *page;
    l1_pgentry_t l1e, nl1e;
    unsigned long gva = curr->arch.pv_vcpu.ldt_base + (off << PAGE_SHIFT);
    int okay;

    BUG_ON(unlikely(in_irq()));

    if ( is_pv_32bit_domain(currd) )
        gva = (u32)gva;
    pv_get_guest_eff_kern_l1e(curr, gva, &l1e);
    if ( unlikely(!(l1e_get_flags(l1e) & _PAGE_PRESENT)) )
        return false;

    gmfn = l1e_get_pfn(l1e);
    page = get_page_from_gfn(currd, gmfn, NULL, P2M_ALLOC);
    if ( unlikely(!page) )
        return false;

    okay = get_page_type(page, PGT_seg_desc_page);
    if ( unlikely(!okay) )
    {
        put_page(page);
        return false;
    }

    nl1e = l1e_from_pfn(page_to_mfn(page), l1e_get_flags(l1e) | _PAGE_RW);

    spin_lock(&curr->arch.pv_vcpu.shadow_ldt_lock);
    l1e_write(&gdt_ldt_ptes(currd, curr)[off + 16], nl1e);
    curr->arch.pv_vcpu.shadow_ldt_mapcnt++;
    spin_unlock(&curr->arch.pv_vcpu.shadow_ldt_lock);

    return true;
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
