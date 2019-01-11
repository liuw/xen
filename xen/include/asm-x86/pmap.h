#ifndef __X86_PMAP_H__
#define __X86_PMAP_H__

/* Large enough for mapping 5 levels of page tables */
#define NUM_FIX_PMAP 5

void pmap_lock(void);
void pmap_unlock(void);
void *pmap_map(struct page_info *page);
void pmap_unmap(void *p);

#endif	/* __X86_PMAP_H__ */
