/*
 * asm-x86/pv/processor.h
 *
 * Vcpu interfaces for PV guests
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

#ifndef __X86_PV_PROCESSOR_H__
#define __X86_PV_PROCESSOR_H__

#ifdef CONFIG_PV

void pv_destroy_gdt(struct vcpu *d);
long pv_set_gdt(struct vcpu *d, unsigned long *frames, unsigned int entries);
bool pv_map_ldt_shadow_page(unsigned int);

#else

#include <xen/errno.h>

static inline void pv_destroy_gdt(struct vcpu *d) {}
static inline long pv_set_gdt(struct vcpu *d, unsigned long *frames,
                              unsigned int entries)
{ return -EINVAL; }
static inline bool pv_map_ldt_shadow_page(unsigned int) { return false; }

#endif

#endif /* __X86_PV_PROCESSOR_H__ */
