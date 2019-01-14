#include <xen/init.h>
#include <xen/mm.h>
#include <xen/spinlock.h>

#include <asm/bitops.h>
#include <asm/fixmap.h>

/*
 * Simple mapping infrastructure to map / unmap pages in fixed map.
 * This is used to set up percpu page table for mapcache, which is
 * used by map domain page infrastructure.
 *
 * There is a restriction that only one CPU can use this
 * infrastructure at a time. So this infrastructure _should not_ be
 * used anywhere else other than the stated purpose above.
 */

static DEFINE_SPINLOCK(lock);
/* Bitmap to track which slot is used */
static unsigned long inuse;

void pmap_lock(void)
{
    spin_lock(&lock);
}

void pmap_unlock(void)
{
    spin_unlock(&lock);
}

void *pmap_map(struct page_info *page)
{
    unsigned int idx;
    void *linear = NULL;
    enum fixed_addresses slot;

    ASSERT(!in_irq());
    ASSERT(spin_is_locked(&lock));

    idx = find_first_zero_bit(&inuse, NUM_FIX_PMAP);
    if ( idx == NUM_FIX_PMAP )
        panic("Out of PMAP slots\n");

    __set_bit(idx, &inuse);

    slot = idx + FIX_PMAP_BEGIN;
    ASSERT(slot >= FIX_PMAP_BEGIN && slot <= FIX_PMAP_END);

    set_fixmap(slot, mfn_x(page_to_mfn(page)));
    linear = (void *)__fix_to_virt(slot);

    printk(" XXX mapping %"PRI_mfn" to %p with idx %u\n",
           mfn_x(page_to_mfn(page)), linear, idx);

    return linear;
}

void pmap_unmap(void *p)
{
    unsigned int idx;
    enum fixed_addresses slot = __virt_to_fix((unsigned long)p);

    ASSERT(!in_irq());
    ASSERT(slot >= FIX_PMAP_BEGIN && slot <= FIX_PMAP_END);
    ASSERT(spin_is_locked(&lock));

    idx = slot - FIX_PMAP_BEGIN;
    __clear_bit(idx, &inuse);
    clear_fixmap(slot);

    printk(" XXX unmapping %p with idx %u\n",  p, idx);
}

static void __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(sizeof(inuse) * BITS_PER_LONG < NUM_FIX_PMAP);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
