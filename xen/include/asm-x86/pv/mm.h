/*
 * asm-x86/pv/mm.h
 *
 * Memory management interfaces for PV guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
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

#ifndef __X86_PV_MM_H__
#define __X86_PV_MM_H__


#ifdef CONFIG_PV

void pv_get_guest_eff_l1e(unsigned long addr, l1_pgentry_t *eff_l1e);

void pv_get_guest_eff_kern_l1e(struct vcpu *v, unsigned long addr,
                               void *eff_l1e);

bool pv_update_intpte(intpte_t *p, intpte_t old, intpte_t new,
                      unsigned long mfn, struct vcpu *v, int preserve_ad);
/*
 * Macro that wraps the appropriate type-changes around update_intpte().
 * Arguments are: type, ptr, old, new, mfn, vcpu
 */
#define UPDATE_ENTRY(_t,_p,_o,_n,_m,_v,_ad)                            \
    pv_update_intpte(&_t ## e_get_intpte(*(_p)),                       \
                     _t ## e_get_intpte(_o), _t ## e_get_intpte(_n),   \
                     (_m), (_v), (_ad))

#else

static inline void pv_get_guest_eff_l1e(unsigned long addr,
                                        l1_pgentry_t *eff_l1e)
{}

static inline void pv_get_guest_eff_kern_l1e(struct vcpu *v, unsigned long addr,
                                             void *eff_l1e)
{}

static inline bool pv_update_intpte(intpte_t *p, intpte_t old, intpte_t new,
                                    unsigned long mfn, struct vcpu *v,
                                    int preserve_ad)
{ return false; }

#endif

#endif /* __X86_PV_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
