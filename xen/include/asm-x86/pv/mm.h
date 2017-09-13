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

int pv_ro_page_fault(unsigned long addr, struct cpu_user_regs *regs);

long pv_set_gdt(struct vcpu *d, unsigned long *frames, unsigned int entries);
void pv_destroy_gdt(struct vcpu *d);

bool pv_map_ldt_shadow_page(unsigned int off);

#else

#include <xen/errno.h>

static inline int pv_ro_page_fault(unsigned long addr,
                                   struct cpu_user_regs *regs)
{
    return 0;
}

static inline long pv_set_gdt(struct vcpu *d, unsigned long *frames,
                              unsigned int entries)
{ return -EINVAL; }
static inline void pv_destroy_gdt(struct vcpu *d) {}

static inline bool pv_map_ldt_shadow_page(unsigned int off) { return false; }

#endif

#endif /* __X86_PV_MM_H__ */
