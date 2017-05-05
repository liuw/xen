/*
 * pv/traps.h
 *
 * PV guest traps interface definitions
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

#ifndef __X86_PV_TRAPS_H__
#define __X86_PV_TRAPS_H__

#ifdef CONFIG_PV

#include <public/xen.h>

int emulate_privileged_op(struct cpu_user_regs *regs);
void emulate_gate_op(struct cpu_user_regs *regs);
int emulate_forced_invalid_op(struct cpu_user_regs *regs);
int emulate_invalid_rdtscp(struct cpu_user_regs *regs);

void pv_percpu_traps_init(void);

#else  /* !CONFIG_PV */

#include <xen/errno.h>

int emulate_privileged_op(struct cpu_user_regs *regs) { return -EOPNOTSUPP; }
void emulate_gate_op(struct cpu_user_regs *regs) {}
int emulate_forced_invalid_op(struct cpu_user_regs *regs) { return -EOPNOTSUPP; }
int emulate_invalid_rdtscp(struct cpu_user_regs *regs) { return -EOPNOTSUPP; }

void pv_percpu_traps_init(void) {}

#endif	/* CONFIG_PV */

#endif	/* __X86_PV_TRAPS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
