/******************************************************************************
 * arch/x86/pv/mm.c
 *
 * Memory management code for PV guests
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

#include <asm/pv/mm.h>

/*
 * PTE updates can be done with ordinary writes except:
 *  1. Debug builds get extra checking by using CMPXCHG[8B].
 */
#if !defined(NDEBUG)
#define PTE_UPDATE_WITH_CMPXCHG
#endif

/* Read a PV guest's l1e that maps this virtual address. */
void pv_get_guest_eff_l1e(unsigned long addr, l1_pgentry_t *eff_l1e)
{
    ASSERT(!paging_mode_translate(current->domain));
    ASSERT(!paging_mode_external(current->domain));

    if ( unlikely(!__addr_ok(addr)) ||
         __copy_from_user(eff_l1e,
                          &__linear_l1_table[l1_linear_offset(addr)],
                          sizeof(l1_pgentry_t)) )
        *eff_l1e = l1e_empty();
}

/*
 * Read the guest's l1e that maps this address, from the kernel-mode
 * page tables.
 */
void pv_get_guest_eff_kern_l1e(struct vcpu *v, unsigned long addr,
                               void *eff_l1e)
{
    const bool user_mode = !(v->arch.flags & TF_kernel_mode);

    if ( user_mode )
        toggle_guest_mode(v);

    pv_get_guest_eff_l1e(addr, eff_l1e);

    if ( user_mode )
        toggle_guest_mode(v);
}

/* Get a mapping of a PV guest's l1e for this virtual address. */
l1_pgentry_t *pv_map_guest_l1e(unsigned long addr, unsigned long *gl1mfn)
{
    l2_pgentry_t l2e;

    ASSERT(!paging_mode_translate(current->domain));
    ASSERT(!paging_mode_external(current->domain));

    if ( unlikely(!__addr_ok(addr)) )
        return NULL;

    /* Find this l1e and its enclosing l1mfn in the linear map. */
    if ( __copy_from_user(&l2e,
                          &__linear_l2_table[l2_linear_offset(addr)],
                          sizeof(l2_pgentry_t)) )
        return NULL;

    /* Check flags that it will be safe to read the l1e. */
    if ( (l2e_get_flags(l2e) & (_PAGE_PRESENT | _PAGE_PSE)) != _PAGE_PRESENT )
        return NULL;

    *gl1mfn = l2e_get_pfn(l2e);

    return (l1_pgentry_t *)map_domain_page(_mfn(*gl1mfn)) +
           l1_table_offset(addr);
}

/* Pull down the mapping we got from pv_map_guest_l1e(). */
void pv_unmap_guest_l1e(void *p)
{
    unmap_domain_page(p);
}

/*
 * How to write an entry to the guest pagetables.
 * Returns false for failure (pointer not valid), true for success.
 */
bool pv_update_intpte(intpte_t *p, intpte_t old, intpte_t new,
                      unsigned long mfn, struct vcpu *v, int preserve_ad)
{
    bool rv = true;

#ifndef PTE_UPDATE_WITH_CMPXCHG
    if ( !preserve_ad )
    {
        rv = paging_write_guest_entry(v, p, new, _mfn(mfn));
    }
    else
#endif
    {
        intpte_t t = old;

        for ( ; ; )
        {
            intpte_t _new = new;

            if ( preserve_ad )
                _new |= old & (_PAGE_ACCESSED | _PAGE_DIRTY);

            rv = paging_cmpxchg_guest_entry(v, p, &t, _new, _mfn(mfn));
            if ( unlikely(rv == 0) )
            {
                gdprintk(XENLOG_WARNING,
                         "Failed to update %" PRIpte " -> %" PRIpte
                         ": saw %" PRIpte "\n", old, _new, t);
                break;
            }

            if ( t == old )
                break;

            /* Allowed to change in Accessed/Dirty flags only. */
            BUG_ON((t ^ old) & ~(intpte_t)(_PAGE_ACCESSED|_PAGE_DIRTY));

            old = t;
        }
    }
    return rv;
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
