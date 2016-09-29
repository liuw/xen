#ifndef _GCOV_H_
#define _GCOV_H_

#include <xen/guest_access.h>
#include <xen/types.h>

/*
 * Profiling data types used for gcc 3.4 and above - these are defined by
 * gcc and need to be kept as close to the original definition as possible to
 * remain compatible.
 */
#define GCOV_DATA_MAGIC		((unsigned int) 0x67636461)
#define GCOV_TAG_FUNCTION	((unsigned int) 0x01000000)
#define GCOV_TAG_COUNTER_BASE	((unsigned int) 0x01a10000)
#define GCOV_TAG_FOR_COUNTER(count)					\
	(GCOV_TAG_COUNTER_BASE + ((unsigned int) (count) << 17))

#if BITS_PER_LONG >= 64
typedef long gcov_type;
#else
typedef long long gcov_type;
#endif

/* Opaque gcov_info -- tied to specific gcc gcov formats */
struct gcov_info;

void gcov_info_link(struct gcov_info *info);
struct gcov_info *gcov_info_next(struct gcov_info *info);
void gcov_info_reset(struct gcov_info *info);
const char *gcov_info_filename(struct gcov_info *info);
size_t gcov_info_to_gcda(char *buffer, struct gcov_info *info);

size_t gcov_store_u32(void *buffer, size_t off, u32 v);
size_t gcov_store_u64(void *buffer, size_t off, u64 v);

#endif	/* _GCOV_H_ */
