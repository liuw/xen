/*
 * Copyright (C) 2014      Citrix Ltd.
 * Author Wei Liu <wei.liu2@citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */
#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxl_internal.h"
#include <stdlib.h>

/* Sort vmemranges in ascending order with "start" */
static int compare_vmemrange(const void *a, const void *b)
{
    const xen_vmemrange_t *x = a, *y = b;
    if (x->start < y->start)
        return -1;
    if (x->start > y->start)
        return 1;
    return 0;
}

/* Check if vNUMA configuration is valid:
 *  1. all pnodes inside vnode_to_pnode array are valid
 *  2. one vcpu belongs to and only belongs to one vnode
 *  3. each vmemrange is valid and doesn't overlap with each other
 */
int libxl__vnuma_config_check(libxl__gc *gc,
			      const libxl_domain_build_info *b_info,
                              const libxl__domain_build_state *state)
{
    int i, j, rc = ERROR_INVAL, nr_nodes;
    libxl_numainfo *ninfo = NULL;
    uint64_t total_ram = 0;
    libxl_bitmap cpumap;
    libxl_vnode_info *p;

    libxl_bitmap_init(&cpumap);

    /* Check pnode specified is valid */
    ninfo = libxl_get_numainfo(CTX, &nr_nodes);
    if (!ninfo) {
        LIBXL__LOG(CTX, LIBXL__LOG_ERROR, "libxl_get_numainfo failed");
        goto out;
    }

    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        uint32_t pnode;

        p = &b_info->vnuma_nodes[i];
        pnode = p->pnode;

        /* The pnode specified is not valid? */
        if (pnode >= nr_nodes) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                       "Invalid pnode %d specified",
                       pnode);
            goto out;
        }

        total_ram += p->mem;
    }

    if (total_ram != (b_info->max_memkb >> 10)) {
        LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                   "Total ram in vNUMA configuration 0x%"PRIx64" while maxmem specified 0x%"PRIx64,
                   total_ram, (b_info->max_memkb >> 10));
        goto out;
    }

    /* Check vcpu mapping */
    libxl_cpu_bitmap_alloc(CTX, &cpumap, b_info->max_vcpus);
    libxl_bitmap_set_none(&cpumap);
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        p = &b_info->vnuma_nodes[i];
        libxl_for_each_set_bit(j, p->vcpus) {
            if (!libxl_bitmap_test(&cpumap, j))
                libxl_bitmap_set(&cpumap, j);
            else {
                LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                           "Try to assign vcpu %d to vnode %d while it's already assigned to other vnode",
                           j, i);
                goto out;
            }
        }
    }

    for (i = 0; i < b_info->max_vcpus; i++) {
        if (!libxl_bitmap_test(&cpumap, i)) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                       "Vcpu %d is not assigned to any vnode", i);
            goto out;
        }
    }

    /* Check vmemranges */
    qsort(state->vmemranges, state->num_vmemranges, sizeof(xen_vmemrange_t),
          compare_vmemrange);

    for (i = 0; i < state->num_vmemranges; i++) {
        if (state->vmemranges[i].end < state->vmemranges[i].start) {
                LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                           "Vmemrange end < start");
                goto out;
        }
    }

    for (i = 0; i < state->num_vmemranges - 1; i++) {
        if (state->vmemranges[i].end > state->vmemranges[i+1].start) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                       "Vmemranges overlapped, 0x%"PRIx64"-0x%"PRIx64", 0x%"PRIx64"-0x%"PRIx64,
                       state->vmemranges[i].start, state->vmemranges[i].end,
                       state->vmemranges[i+1].start, state->vmemranges[i+1].end);
            goto out;
        }
    }

    rc = 0;
out:
    if (ninfo) libxl_numainfo_dispose(ninfo);
    libxl_bitmap_dispose(&cpumap);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
