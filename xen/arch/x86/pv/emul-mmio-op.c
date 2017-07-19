/******************************************************************************
 * arch/x86/emul-mmio-op.c
 *
 * Readonly MMIO emulation for PV guests
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

#include <xen/rangeset.h>
#include <xen/sched.h>

#include <asm/domain.h>
#include <asm/mm.h>
#include <asm/pci.h>
#include <asm/pv/mm.h>

#include "emulate.h"

/*************************
 * fault handling for read-only MMIO pages
 */

static const struct x86_emulate_ops mmio_ro_emulate_ops = {
    .read       = x86emul_unhandleable_rw,
    .insn_fetch = pv_emul_ptwr_read,
    .write      = mmio_ro_emulated_write,
    .validate   = pv_emul_is_mem_write,
    .cpuid      = pv_emul_cpuid,
};

int mmcfg_intercept_write(enum x86_segment seg, unsigned long offset,
                          void *p_data, unsigned int bytes,
                          struct x86_emulate_ctxt *ctxt)
{
    struct mmio_ro_emulate_ctxt *mmio_ctxt = ctxt->data;

    /*
     * Only allow naturally-aligned stores no wider than 4 bytes to the
     * original %cr2 address.
     */
    if ( ((bytes | offset) & (bytes - 1)) || bytes > 4 || !bytes ||
         offset != mmio_ctxt->cr2 )
    {
        gdprintk(XENLOG_WARNING, "bad write (cr2=%lx, addr=%lx, bytes=%u)\n",
                mmio_ctxt->cr2, offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    offset &= 0xfff;
    if ( pci_conf_write_intercept(mmio_ctxt->seg, mmio_ctxt->bdf,
                                  offset, bytes, p_data) >= 0 )
        pci_mmcfg_write(mmio_ctxt->seg, PCI_BUS(mmio_ctxt->bdf),
                        PCI_DEVFN2(mmio_ctxt->bdf), offset, bytes,
                        *(uint32_t *)p_data);

    return X86EMUL_OKAY;
}

static const struct x86_emulate_ops mmcfg_intercept_ops = {
    .read       = x86emul_unhandleable_rw,
    .insn_fetch = pv_emul_ptwr_read,
    .write      = mmcfg_intercept_write,
    .validate   = pv_emul_is_mem_write,
    .cpuid      = pv_emul_cpuid,
};

/* Check if guest is trying to modify a r/o MMIO page. */
int mmio_ro_do_page_fault(struct vcpu *v, unsigned long addr,
                          struct cpu_user_regs *regs)
{
    l1_pgentry_t pte;
    unsigned long mfn;
    unsigned int addr_size = is_pv_32bit_vcpu(v) ? 32 : BITS_PER_LONG;
    struct mmio_ro_emulate_ctxt mmio_ro_ctxt = { .cr2 = addr };
    struct x86_emulate_ctxt ctxt = {
        .regs = regs,
        .vendor = v->domain->arch.cpuid->x86_vendor,
        .addr_size = addr_size,
        .sp_size = addr_size,
        .lma = !is_pv_32bit_vcpu(v),
        .data = &mmio_ro_ctxt,
    };
    int rc;

    /* Attempt to read the PTE that maps the VA being accessed. */
    pv_get_guest_eff_l1e(addr, &pte);

    /* We are looking only for read-only mappings of MMIO pages. */
    if ( ((l1e_get_flags(pte) & (_PAGE_PRESENT|_PAGE_RW)) != _PAGE_PRESENT) )
        return 0;

    mfn = l1e_get_pfn(pte);
    if ( mfn_valid(_mfn(mfn)) )
    {
        struct page_info *page = mfn_to_page(mfn);
        struct domain *owner = page_get_owner_and_reference(page);

        if ( owner )
            put_page(page);
        if ( owner != dom_io )
            return 0;
    }

    if ( !rangeset_contains_singleton(mmio_ro_ranges, mfn) )
        return 0;

    if ( pci_ro_mmcfg_decode(mfn, &mmio_ro_ctxt.seg, &mmio_ro_ctxt.bdf) )
        rc = x86_emulate(&ctxt, &mmcfg_intercept_ops);
    else
        rc = x86_emulate(&ctxt, &mmio_ro_emulate_ops);

    switch ( rc )
    {
    case X86EMUL_EXCEPTION:
        /*
         * This emulation only covers writes to MMCFG space or read-only MFNs.
         * We tolerate #PF (from hitting an adjacent page or a successful
         * concurrent pagetable update).  Anything else is an emulation bug,
         * or a guest playing with the instruction stream under Xen's feet.
         */
        if ( ctxt.event.type == X86_EVENTTYPE_HW_EXCEPTION &&
             ctxt.event.vector == TRAP_page_fault )
            pv_inject_event(&ctxt.event);
        else
            gdprintk(XENLOG_WARNING,
                     "Unexpected event (type %u, vector %#x) from emulation\n",
                     ctxt.event.type, ctxt.event.vector);

        /* Fallthrough */
    case X86EMUL_OKAY:

        if ( ctxt.retire.singlestep )
            pv_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);

        /* Fallthrough */
    case X86EMUL_RETRY:
        perfc_incr(ptwr_emulations);
        return EXCRET_fault_fixed;
    }

    return 0;
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
