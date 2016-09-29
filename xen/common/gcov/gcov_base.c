/*
 * Common code across gcov implementations
 *
 * Copyright Citrix Systems R&D UK
 * Author(s): Wei Liu <wei.liu2@citrix.com>
 *
 *    Uses gcc-internal data definitions.
 *    Based on the gcov-kernel patch by:
 *       Hubertus Franke <frankeh@us.ibm.com>
 *       Nigel Hinds <nhinds@us.ibm.com>
 *       Rajan Ravindran <rajancr@us.ibm.com>
 *       Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *       Paul Larson
 */

#include "gcov.h"

/*
 * __gcov_init is called by gcc-generated constructor code for each object
 * file compiled with -fprofile-arcs.
 *
 * Although this function is called only during initialization is called from
 * a .text section which is still present after initialization so not declare
 * as __init.
 */
void __gcov_init(struct gcov_info *info)
{
    /* Link all gcov info together. */
    gcov_info_link(info);
}

/*
 * These functions may be referenced by gcc-generated profiling code but serve
 * no function for Xen.
 */
void __gcov_flush(void)
{
    /* Unused. */
}

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
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
