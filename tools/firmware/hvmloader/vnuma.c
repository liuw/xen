/*
 * vnuma.c: obtain vNUMA information from hypervisor
 *
 * Copyright (c) 2014 Wei Liu, Citrix Systems (R&D) Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "util.h"
#include "hypercall.h"
#include "vnuma.h"
#include "errno.h"

unsigned int nr_vnodes, nr_vmemranges;
unsigned int *vcpu_to_vnode, *vdistance;
xen_vmemrange_t *vmemrange;

void init_vnuma_info(void)
{
    int rc, retry = 0;
    struct xen_vnuma_topology_info vnuma_topo;

    vcpu_to_vnode = scratch_alloc(sizeof(uint32_t) * hvm_info->nr_vcpus, 0);

    rc = -EAGAIN;
    while ( rc == -EAGAIN && retry < 10 )
    {
        vnuma_topo.domid = DOMID_SELF;
        vnuma_topo.pad = 0;
        vnuma_topo.nr_vcpus = 0;
        vnuma_topo.nr_vnodes = 0;
        vnuma_topo.nr_vmemranges = 0;

        set_xen_guest_handle(vnuma_topo.vdistance.h, NULL);
        set_xen_guest_handle(vnuma_topo.vcpu_to_vnode.h, NULL);
        set_xen_guest_handle(vnuma_topo.vmemrange.h, NULL);

        rc = hypercall_memory_op(XENMEM_get_vnumainfo, &vnuma_topo);

        if ( rc == -EOPNOTSUPP )
            return;

        if ( rc != -ENOBUFS )
            break;

        ASSERT(vnuma_topo.nr_vcpus == hvm_info->nr_vcpus);

        vdistance = scratch_alloc(sizeof(uint32_t) * vnuma_topo.nr_vnodes *
                                  vnuma_topo.nr_vnodes, 0);
        vmemrange = scratch_alloc(sizeof(xen_vmemrange_t) *
                                  vnuma_topo.nr_vmemranges, 0);

        set_xen_guest_handle(vnuma_topo.vdistance.h, vdistance);
        set_xen_guest_handle(vnuma_topo.vcpu_to_vnode.h, vcpu_to_vnode);
        set_xen_guest_handle(vnuma_topo.vmemrange.h, vmemrange);

        rc = hypercall_memory_op(XENMEM_get_vnumainfo, &vnuma_topo);

        retry++;
    }

    if ( rc < 0 )
    {
        printf("Failed to retrieve vNUMA information, rc = %d\n", rc);
        return;
    }

    nr_vnodes = vnuma_topo.nr_vnodes;
    nr_vmemranges = vnuma_topo.nr_vmemranges;

    return;
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
