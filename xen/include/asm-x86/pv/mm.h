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

#define adjust_guest_l1e(pl1e, d)                                            \
    do {                                                                     \
        if ( likely(l1e_get_flags((pl1e)) & _PAGE_PRESENT) &&                \
             likely(!is_pv_32bit_domain(d)) )                                \
        {                                                                    \
            /* _PAGE_GUEST_KERNEL page cannot have the Global bit set. */    \
            if ( (l1e_get_flags((pl1e)) & (_PAGE_GUEST_KERNEL|_PAGE_GLOBAL)) \
                 == (_PAGE_GUEST_KERNEL|_PAGE_GLOBAL) )                      \
                gdprintk(XENLOG_WARNING,                                     \
                         "Global bit is set to kernel page %lx\n",           \
                         l1e_get_pfn((pl1e)));                               \
            if ( !(l1e_get_flags((pl1e)) & _PAGE_USER) )                     \
                l1e_add_flags((pl1e), (_PAGE_GUEST_KERNEL|_PAGE_USER));      \
            if ( !(l1e_get_flags((pl1e)) & _PAGE_GUEST_KERNEL) )             \
                l1e_add_flags((pl1e), (_PAGE_GLOBAL|_PAGE_USER));            \
        }                                                                    \
    } while ( 0 )

#define adjust_guest_l2e(pl2e, d)                               \
    do {                                                        \
        if ( likely(l2e_get_flags((pl2e)) & _PAGE_PRESENT) &&   \
             likely(!is_pv_32bit_domain(d)) )                   \
            l2e_add_flags((pl2e), _PAGE_USER);                  \
    } while ( 0 )

#define adjust_guest_l3e(pl3e, d)                                   \
    do {                                                            \
        if ( likely(l3e_get_flags((pl3e)) & _PAGE_PRESENT) )        \
            l3e_add_flags((pl3e), likely(!is_pv_32bit_domain(d)) ?  \
                                         _PAGE_USER :               \
                                         _PAGE_USER|_PAGE_RW);      \
    } while ( 0 )

#define adjust_guest_l4e(pl4e, d)                               \
    do {                                                        \
        if ( likely(l4e_get_flags((pl4e)) & _PAGE_PRESENT) &&   \
             likely(!is_pv_32bit_domain(d)) )                   \
            l4e_add_flags((pl4e), _PAGE_USER);                  \
    } while ( 0 )

#define unadjust_guest_l3e(pl3e, d)                                         \
    do {                                                                    \
        if ( unlikely(is_pv_32bit_domain(d)) &&                             \
             likely(l3e_get_flags((pl3e)) & _PAGE_PRESENT) )                \
            l3e_remove_flags((pl3e), _PAGE_USER|_PAGE_RW|_PAGE_ACCESSED);   \
    } while ( 0 )

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

l1_pgentry_t *pv_map_guest_l1e(unsigned long addr, unsigned long *gl1mfn);
void pv_unmap_guest_l1e(void *p);

void pv_init_guest_l4_table(l4_pgentry_t[], const struct domain *,
                            bool zap_ro_mpt);
void pv_arch_init_memory(void);

int pv_new_guest_cr3(unsigned long pfn);

#else

#include <xen/errno.h>

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

static inline l1_pgentry_t *pv_map_guest_l1e(unsigned long addr,
                                             unsigned long *gl1mfn);
{ return NULL; }

static inline void pv_unmap_guest_l1e(void *p) {}

static inline void pv_init_guest_l4_table(l4_pgentry_t[],
                                          const struct domain *,
                                          bool zap_ro_mpt) {}
static inline void pv_arch_init_memory(void) {}

static inline int pv_new_guest_cr3(unsigned long pfn) { return -EINVAL; }

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
