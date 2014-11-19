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
#include "libxl_arch.h"
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

/* Build vmemranges for PV guest */
int libxl__vnuma_build_vmemrange_pv(libxl__gc *gc,
                                    uint32_t domid,
                                    libxl_domain_build_info *b_info,
                                    libxl__domain_build_state *state)
{
    int i;
    uint64_t next;
    xen_vmemrange_t *v = NULL;

    assert(state->vmemranges == NULL);

    /* Generate one vmemrange for each virtual node. */
    next = 0;
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[i];

        v = libxl__realloc(gc, v, sizeof(*v) * (i+1));

        v[i].start = next;
        v[i].end = next + (p->mem << 20); /* mem is in MiB */
        v[i].flags = 0;
        v[i].nid = i;

        next = v[i].end;
    }

    state->vmemranges = v;
    state->num_vmemranges = i;

    return libxl__arch_vnuma_build_vmemrange(gc, domid, b_info, state);
}

/* Build vmemranges for HVM guest */
int libxl__vnuma_build_vmemrange_hvm(libxl__gc *gc,
                                     uint32_t domid,
                                     libxl_domain_build_info *b_info,
                                     libxl__domain_build_state *state,
                                     struct xc_hvm_build_args *args)
{
    uint64_t hole_start, hole_end, next;
    int i, x;
    xen_vmemrange_t *v;

    /* Derive vmemranges from vnode size and memory hole.
     *
     * Guest physical address space layout:
     * [0, hole_start) [hole_start, hole_end) [hole_end, highmem_end)
     */
    hole_start = args->lowmem_end < args->mmio_start ?
        args->lowmem_end : args->mmio_start;
    hole_end = (args->mmio_start + args->mmio_size) > (1ULL << 32) ?
        (args->mmio_start + args->mmio_size) : (1ULL << 32);

    assert(state->vmemranges == NULL);

    next = 0;
    x = 0;
    v = NULL;
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[i];
        uint64_t remaining = (p->mem << 20);

        while (remaining > 0) {
            uint64_t count = remaining;

            if (next >= hole_start && next < hole_end)
                next = hole_end;
            if ((next < hole_start) && (next + remaining >= hole_start))
                count = hole_start - next;

            v = libxl__realloc(gc, v, sizeof(xen_vmemrange_t) * (x + 1));
            v[x].start = next;
            v[x].end = next + count;
            v[x].flags = 0;
            v[x].nid = i;

            x++;
            remaining -= count;
            next += count;
        }
    }

    state->vmemranges = v;
    state->num_vmemranges = x;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
