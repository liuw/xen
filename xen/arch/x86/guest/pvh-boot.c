/******************************************************************************
 * arch/x86/guest/pvh-boot.c
 *
 * PVH boot time support
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
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>

#include <asm/e820.h>
#include <asm/guest.h>

#include <public/arch-x86/hvm/start_info.h>

/* Initialised in head.S, before .bss is zeroed. */
bool pvh_boot __initdata;
uint32_t pvh_start_info_pa __initdata;

static multiboot_info_t __initdata pvh_mbi;
static module_t __initdata pvh_mbi_mods[32];
static char *__initdata pvh_loader = "PVH Directboot";

static void __init convert_pvh_info(void)
{
    struct hvm_start_info *pvh_info = __va(pvh_start_info_pa);
    struct hvm_modlist_entry *entry;
    module_t *mod;
    unsigned int i;

    ASSERT(pvh_info->magic == XEN_HVM_START_MAGIC_VALUE);

    /*
     * Turn hvm_start_info into mbi. Luckily all modules are placed under 4GB
     * boundary on x86.
     */
    pvh_mbi.flags = MBI_CMDLINE | MBI_MODULES | MBI_LOADERNAME;

    ASSERT(!(pvh_info->cmdline_paddr >> 32));
    pvh_mbi.cmdline = pvh_info->cmdline_paddr;
    pvh_mbi.boot_loader_name = __pa(pvh_loader);

    ASSERT(pvh_info->nr_modules < 32);
    pvh_mbi.mods_count = pvh_info->nr_modules;
    pvh_mbi.mods_addr = __pa(pvh_mbi_mods);

    mod = pvh_mbi_mods;
    entry = __va(pvh_info->modlist_paddr);
    for ( i = 0; i < pvh_info->nr_modules; i++ )
    {
        ASSERT(!(entry[i].paddr >> 32));

        mod[i].mod_start = entry[i].paddr;
        mod[i].mod_end   = entry[i].paddr + entry[i].size;
        mod[i].string    = entry[i].cmdline_paddr;
    }
}

static void __init get_memory_map(void)
{
    struct xen_memory_map memmap = {
        .nr_entries = E820MAX,
        .buffer.p = e820_raw.map,
    };
    int rc = xen_hypercall_memory_op(XENMEM_memory_map, &memmap);

    ASSERT(rc == 0);
    e820_raw.nr_map = memmap.nr_entries;

    /* :( Various toolstacks don't sort the memory map. */
    sanitize_e820_map(e820_raw.map, &e820_raw.nr_map);
}

multiboot_info_t *__init pvh_init(void)
{
    convert_pvh_info();

    probe_hypervisor();
    ASSERT(xen_guest);

    get_memory_map();

    return &pvh_mbi;
}

void __init pvh_print_info(void)
{
    struct hvm_start_info *pvh_info = __va(pvh_start_info_pa);
    struct hvm_modlist_entry *entry;
    unsigned int i;

    ASSERT(pvh_info->magic == XEN_HVM_START_MAGIC_VALUE);

    printk("PVH start info: (pa %08x)\n", pvh_start_info_pa);
    printk("  version:    %u\n", pvh_info->version);
    printk("  flags:      %#"PRIx32"\n", pvh_info->flags);
    printk("  nr_modules: %u\n", pvh_info->nr_modules);
    printk("  modlist_pa: %016"PRIx64"\n", pvh_info->modlist_paddr);
    printk("  cmdline_pa: %016"PRIx64"\n", pvh_info->cmdline_paddr);
    if ( pvh_info->cmdline_paddr )
        printk("  cmdline:    '%s'\n",
               (char *)__va(pvh_info->cmdline_paddr));
    printk("  rsdp_pa:    %016"PRIx64"\n", pvh_info->rsdp_paddr);

    entry = __va(pvh_info->modlist_paddr);
    for ( i = 0; i < pvh_info->nr_modules; i++ )
    {
        printk("    mod[%u].pa:         %016"PRIx64"\n", i, entry[i].paddr);
        printk("    mod[%u].size:       %016"PRIu64"\n", i, entry[i].size);
        printk("    mod[%u].cmdline_pa: %016"PRIx64"\n",
               i, entry[i].cmdline_paddr);
        if ( entry[i].cmdline_paddr )
            printk("    mod[%u].cmdline:    '%s'\n", i,
                   (char *)__va(entry[i].cmdline_paddr));
    }
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
