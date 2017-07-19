/******************************************************************************
 * arch/x86/pv/emul-ptwr-op.c
 *
 * Emulate writable pagetable for PV guests
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

#include <xen/guest_access.h>
#include <xen/trace.h>

#include <asm/pv/mm.h>

#include "emulate.h"

/*************************
 * Writable Pagetables
 */

struct ptwr_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;
    unsigned long cr2;
    l1_pgentry_t  pte;
};

int pv_emul_ptwr_read(enum x86_segment seg, unsigned long offset, void *p_data,
                      unsigned int bytes, struct x86_emulate_ctxt *ctxt)
{
    unsigned int rc = bytes;
    unsigned long addr = offset;

    if ( !__addr_ok(addr) ||
         (rc = __copy_from_user(p_data, (void *)addr, bytes)) )
    {
        x86_emul_pagefault(0, addr + bytes - rc, ctxt);  /* Read fault. */
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

static int ptwr_emulated_update(unsigned long addr, paddr_t old, paddr_t val,
                                unsigned int bytes, unsigned int do_cmpxchg,
                                struct ptwr_emulate_ctxt *ptwr_ctxt)
{
    unsigned long mfn;
    unsigned long unaligned_addr = addr;
    struct page_info *page;
    l1_pgentry_t pte, ol1e, nl1e, *pl1e;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    int ret;

    /* Only allow naturally-aligned stores within the original %cr2 page. */
    if ( unlikely(((addr ^ ptwr_ctxt->cr2) & PAGE_MASK) ||
                  (addr & (bytes - 1))) )
    {
        gdprintk(XENLOG_WARNING, "bad access (cr2=%lx, addr=%lx, bytes=%u)\n",
                 ptwr_ctxt->cr2, addr, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    /* Turn a sub-word access into a full-word access. */
    if ( bytes != sizeof(paddr_t) )
    {
        paddr_t      full;
        unsigned int rc, offset = addr & (sizeof(paddr_t) - 1);

        /* Align address; read full word. */
        addr &= ~(sizeof(paddr_t) - 1);
        if ( (rc = copy_from_user(&full, (void *)addr, sizeof(paddr_t))) != 0 )
        {
            x86_emul_pagefault(0, /* Read fault. */
                               addr + sizeof(paddr_t) - rc,
                               &ptwr_ctxt->ctxt);
            return X86EMUL_EXCEPTION;
        }
        /* Mask out bits provided by caller. */
        full &= ~((((paddr_t)1 << (bytes * 8)) - 1) << (offset * 8));
        /* Shift the caller value and OR in the missing bits. */
        val  &= (((paddr_t)1 << (bytes * 8)) - 1);
        val <<= (offset) * 8;
        val  |= full;
        /* Also fill in missing parts of the cmpxchg old value. */
        old  &= (((paddr_t)1 << (bytes * 8)) - 1);
        old <<= (offset) * 8;
        old  |= full;
    }

    pte  = ptwr_ctxt->pte;
    mfn  = l1e_get_pfn(pte);
    page = mfn_to_page(mfn);

    /* We are looking only for read-only mappings of p.t. pages. */
    ASSERT((l1e_get_flags(pte) & (_PAGE_RW|_PAGE_PRESENT)) == _PAGE_PRESENT);
    ASSERT(mfn_valid(_mfn(mfn)));
    ASSERT((page->u.inuse.type_info & PGT_type_mask) == PGT_l1_page_table);
    ASSERT((page->u.inuse.type_info & PGT_count_mask) != 0);
    ASSERT(page_get_owner(page) == d);

    /* Check the new PTE. */
    nl1e = l1e_from_intpte(val);
    switch ( ret = get_page_from_l1e(nl1e, d, d) )
    {
    default:
        if ( is_pv_32bit_domain(d) && (bytes == 4) && (unaligned_addr & 4) &&
             !do_cmpxchg && (l1e_get_flags(nl1e) & _PAGE_PRESENT) )
        {
            /*
             * If this is an upper-half write to a PAE PTE then we assume that
             * the guest has simply got the two writes the wrong way round. We
             * zap the PRESENT bit on the assumption that the bottom half will
             * be written immediately after we return to the guest.
             */
            gdprintk(XENLOG_DEBUG, "ptwr_emulate: fixing up invalid PAE PTE %"
                     PRIpte"\n", l1e_get_intpte(nl1e));
            l1e_remove_flags(nl1e, _PAGE_PRESENT);
        }
        else
        {
            gdprintk(XENLOG_WARNING, "could not get_page_from_l1e()\n");
            return X86EMUL_UNHANDLEABLE;
        }
        break;
    case 0:
        break;
    case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
        ASSERT(!(ret & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
        l1e_flip_flags(nl1e, ret);
        break;
    }

    adjust_guest_l1e(nl1e, d);

    /* Checked successfully: do the update (write or cmpxchg). */
    pl1e = map_domain_page(_mfn(mfn));
    pl1e = (l1_pgentry_t *)((unsigned long)pl1e + (addr & ~PAGE_MASK));
    if ( do_cmpxchg )
    {
        bool okay;
        intpte_t t = old;

        ol1e = l1e_from_intpte(old);
        okay = paging_cmpxchg_guest_entry(v, &l1e_get_intpte(*pl1e),
                                          &t, l1e_get_intpte(nl1e), _mfn(mfn));
        okay = (okay && t == old);

        if ( !okay )
        {
            unmap_domain_page(pl1e);
            put_page_from_l1e(nl1e, d);
            return X86EMUL_RETRY;
        }
    }
    else
    {
        ol1e = *pl1e;
        if ( !UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, mfn, v, 0) )
            BUG();
    }

    trace_ptwr_emulation(addr, nl1e);

    unmap_domain_page(pl1e);

    /* Finally, drop the old PTE. */
    put_page_from_l1e(ol1e, d);

    return X86EMUL_OKAY;
}

static int ptwr_emulated_write(enum x86_segment seg, unsigned long offset,
                               void *p_data, unsigned int bytes,
                               struct x86_emulate_ctxt *ctxt)
{
    paddr_t val = 0;

    if ( (bytes > sizeof(paddr_t)) || (bytes & (bytes - 1)) || !bytes )
    {
        gdprintk(XENLOG_WARNING, "bad write size (addr=%lx, bytes=%u)\n",
                 offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    memcpy(&val, p_data, bytes);

    return ptwr_emulated_update(
        offset, 0, val, bytes, 0,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static int ptwr_emulated_cmpxchg(enum x86_segment seg, unsigned long offset,
                                 void *p_old, void *p_new, unsigned int bytes,
                                 struct x86_emulate_ctxt *ctxt)
{
    paddr_t old = 0, new = 0;

    if ( (bytes > sizeof(paddr_t)) || (bytes & (bytes - 1)) )
    {
        gdprintk(XENLOG_WARNING, "bad cmpxchg size (addr=%lx, bytes=%u)\n",
                 offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    memcpy(&old, p_old, bytes);
    memcpy(&new, p_new, bytes);

    return ptwr_emulated_update(
        offset, old, new, bytes, 1,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static const struct x86_emulate_ops ptwr_emulate_ops = {
    .read       = pv_emul_ptwr_read,
    .insn_fetch = pv_emul_ptwr_read,
    .write      = ptwr_emulated_write,
    .cmpxchg    = ptwr_emulated_cmpxchg,
    .validate   = pv_emul_is_mem_write,
    .cpuid      = pv_emul_cpuid,
};

/* Write page fault handler: check if guest is trying to modify a PTE. */
int ptwr_do_page_fault(struct vcpu *v, unsigned long addr,
                       struct cpu_user_regs *regs)
{
    struct domain *d = v->domain;
    struct page_info *page;
    l1_pgentry_t      pte;
    struct ptwr_emulate_ctxt ptwr_ctxt = {
        .ctxt = {
            .regs = regs,
            .vendor = d->arch.cpuid->x86_vendor,
            .addr_size = is_pv_32bit_domain(d) ? 32 : BITS_PER_LONG,
            .sp_size   = is_pv_32bit_domain(d) ? 32 : BITS_PER_LONG,
            .lma       = !is_pv_32bit_domain(d),
        },
    };
    int rc;

    /* Attempt to read the PTE that maps the VA being accessed. */
    pv_get_guest_eff_l1e(addr, &pte);

    /* We are looking only for read-only mappings of p.t. pages. */
    if ( ((l1e_get_flags(pte) & (_PAGE_PRESENT|_PAGE_RW)) != _PAGE_PRESENT) ||
         rangeset_contains_singleton(mmio_ro_ranges, l1e_get_pfn(pte)) ||
         get_page_from_pagenr(l1e_get_pfn(pte), d) )
        goto bail;

    page = l1e_get_page(pte);
    if ( !page_lock(page) )
    {
        put_page(page);
        goto bail;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        put_page(page);
        goto bail;
    }

    ptwr_ctxt.cr2 = addr;
    ptwr_ctxt.pte = pte;

    rc = x86_emulate(&ptwr_ctxt.ctxt, &ptwr_emulate_ops);

    page_unlock(page);
    put_page(page);

    switch ( rc )
    {
    case X86EMUL_EXCEPTION:
        /*
         * This emulation only covers writes to pagetables which are marked
         * read-only by Xen.  We tolerate #PF (in case a concurrent pagetable
         * update has succeeded on a different vcpu).  Anything else is an
         * emulation bug, or a guest playing with the instruction stream under
         * Xen's feet.
         */
        if ( ptwr_ctxt.ctxt.event.type == X86_EVENTTYPE_HW_EXCEPTION &&
             ptwr_ctxt.ctxt.event.vector == TRAP_page_fault )
            pv_inject_event(&ptwr_ctxt.ctxt.event);
        else
            gdprintk(XENLOG_WARNING,
                     "Unexpected event (type %u, vector %#x) from emulation\n",
                     ptwr_ctxt.ctxt.event.type, ptwr_ctxt.ctxt.event.vector);

        /* Fallthrough */
    case X86EMUL_OKAY:

        if ( ptwr_ctxt.ctxt.retire.singlestep )
            pv_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);

        /* Fallthrough */
    case X86EMUL_RETRY:
        perfc_incr(ptwr_emulations);
        return EXCRET_fault_fixed;
    }

 bail:
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
