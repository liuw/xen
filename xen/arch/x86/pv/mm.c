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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
