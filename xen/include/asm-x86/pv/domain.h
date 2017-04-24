/*
 * pv/domain.h
 *
 * PV guest interface definitions
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

#ifndef __X86_PV_DOMAIN_H__
#define __X86_PV_DOMAIN_H__

void pv_vcpu_destroy(struct vcpu *v);
int pv_vcpu_initialise(struct vcpu *v);
void pv_domain_destroy(struct domain *d);
int pv_domain_initialise(struct domain *d, unsigned int domcr_flags,
                         struct xen_arch_domainconfig *config);

#endif	/* __X86_PV_DOMAIN_H__ */
