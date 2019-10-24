/******************************************************************************
 * arch/x86/guest/hyperv/hyperv.c
 *
 * Support for detecting and running under Hyper-V.
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
 *
 * Copyright (c) 2019 Microsoft.
 */
#include <xen/init.h>

#include <asm/guest.h>
#include <asm/guest/hyperv-tlfs.h>

struct ms_hyperv_info ms_hyperv;
bool hyperv_guest;

bool __init hyperv_probe(void)
{
    uint32_t eax, ebx, ecx, edx;

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
    if ( !((ebx == 0x7263694d) &&  /* "Micr" */
           (ecx == 0x666f736f) &&  /* "osof" */
           (edx == 0x76482074)) )  /* "t Hv" */
        return false;

    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);
    if ( eax != 0x31237648 )    /* Hv#1 */
        return false;

    /* Extract more information from Hyper-V */
    ms_hyperv.features = cpuid_eax(HYPERV_CPUID_FEATURES);
    ms_hyperv.misc_features = cpuid_edx(HYPERV_CPUID_FEATURES);
    ms_hyperv.hints = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);

    if ( ms_hyperv.hints & HV_X64_ENLIGHTENED_VMCS_RECOMMENDED )
        ms_hyperv.nested_features = cpuid_eax(HYPERV_CPUID_NESTED_FEATURES);

    ms_hyperv.max_vp_index = cpuid_eax(HYPERV_CPUID_IMPLEMENT_LIMITS);
    ms_hyperv.max_lp_index = cpuid_ebx(HYPERV_CPUID_IMPLEMENT_LIMITS);

    hyperv_guest = true;

    return true;
}

struct hypervisor_ops hyperv_ops = {
    .name = "Hyper-V",
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
