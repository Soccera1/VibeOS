#include <stddef.h>
#include <stdint.h>

#include "ata.h"
#include "console.h"
#include "fs.h"
#include "gdt.h"
#include "idt.h"
#include "initramfs.h"
#include "io.h"
#include "kmalloc.h"
#include "multiboot2.h"
#include "power.h"
#include "string.h"
#include "syscall.h"
#include "userland.h"
#include "virtio_gpu.h"
#include "virtio_scsi.h"
#include "vm.h"

uint64_t kernel_exit_stack_top;

static uint8_t post_user_stack[65536];

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx) {
    __asm__ volatile("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "a"(leaf), "c"(subleaf));
}

static void enable_user_xsave(void) {
    uint64_t cr0 = read_cr0();
    cr0 &= ~(1ull << 2);  // Clear EM.
    cr0 |= (1ull << 1);   // Set MP.
    cr0 &= ~(1ull << 3);  // Clear TS.
    write_cr0(cr0);

    uint64_t cr4 = read_cr4();
    cr4 |= (1ull << 9);   // OSFXSR
    cr4 |= (1ull << 10);  // OSXMMEXCPT

    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    uint32_t eax7 = 0;
    uint32_t ebx7 = 0;
    uint32_t ecx7 = 0;
    uint32_t edx7 = 0;
    cpuid(7, 0, &eax7, &ebx7, &ecx7, &edx7);
    (void)eax7;
    (void)ecx7;
    (void)edx7;
    if ((ebx7 & (1u << 0)) != 0u) {
        cr4 |= (1ull << 16);  // FSGSBASE
    }

    if ((ecx & (1u << 26)) != 0u && (ecx & (1u << 28)) != 0u) {
        cr4 |= (1ull << 18);  // OSXSAVE
        write_cr4(cr4);

        uint64_t xcr0 = xgetbv(0);
        xcr0 |= 0x7ull;       // x87 + SSE + AVX
        xsetbv(0, xcr0);
        return;
    }

    write_cr4(cr4);
}

__attribute__((noreturn)) static void kernel_shutdown(void) {
    power_halt();
}

void userland_exit_handler(uint64_t code) {
    console_printf("\n[userland exited: %u]\n", code);
    kernel_shutdown();
}

void kernel_main(uint64_t mb2_info) {
    console_init(mb2_info);
    console_write("VibeOS amd64 monolithic kernel prototype\n");
    power_init(mb2_info);
    kmalloc_init();
    virtio_gpu_init();
    ata_init();
    virtio_scsi_init();

    const struct mb2_tag_module* initramfs_module = mb2_find_module(mb2_info, 0);
    if (initramfs_module == NULL) {
        console_write("No initramfs module provided by bootloader\n");
    } else {
        const uint8_t* start = (const uint8_t*)(uintptr_t)initramfs_module->mod_start;
        size_t size = (size_t)(initramfs_module->mod_end - initramfs_module->mod_start);
        initramfs_init(start, size);
        console_printf("initramfs: %u bytes, %u entries\n", (unsigned)size, (unsigned)initramfs_entry_count());
    }

    const struct mb2_tag_module* usrfs_module = mb2_find_module(mb2_info, 1);
    const uint8_t* usrfs_start = NULL;
    size_t usrfs_size = 0;
    bool usr_from_scsi = false;
    if (usrfs_module != NULL) {
        usrfs_start = (const uint8_t*)(uintptr_t)usrfs_module->mod_start;
        usrfs_size = (size_t)(usrfs_module->mod_end - usrfs_module->mod_start);
    } else if (virtio_scsi_disk_present(0u)) {
        usr_from_scsi = true;
    }
    size_t home_scsi_index = (usr_from_scsi || virtio_scsi_disk_present(1u)) ? 1u : 0u;

    fs_init(usrfs_start, usrfs_size);
    if (fs_usr_mount_ready()) {
        if (usrfs_module != NULL) {
            console_printf("/usr: ext3 module mounted (%u bytes)\n", (unsigned)usrfs_size);
        } else if (usr_from_scsi) {
            console_printf("/usr: ext3 SCSI disk mounted read-only (%u bytes)\n", (unsigned)virtio_scsi_disk_size(0u));
        } else {
            console_write("/usr: ext3 image mounted from /boot/usr.ext3\n");
        }
    } else {
        if (usrfs_module != NULL) {
            console_write("/usr: ext3 module present but mount failed\n");
        } else {
            console_write("/usr: no ext3 module provided and /boot/usr.ext3 unavailable\n");
        }
    }
    if (fs_home_mount_ready()) {
        if (virtio_scsi_disk_present(home_scsi_index)) {
            console_printf("/home: ext3 SCSI disk %u mounted read-write (%u bytes)\n", (unsigned)home_scsi_index,
                           (unsigned)virtio_scsi_disk_size(home_scsi_index));
        } else {
            console_write("/home: ext3 SCSI disk mounted read-write\n");
        }
    } else if (fs_home_ramdisk_ready()) {
        console_write("/home: ramdisk mounted read-write\n");
    } else {
        console_write("/home: no writable ext3 disk attached\n");
    }
    if (ata_scsi_present()) {
        console_printf("scsi: ATA PACKET device present (%u bytes)\n", (unsigned)ata_scsi_size());
    }
    for (size_t i = 0; i < virtio_scsi_disk_count(); ++i) {
        if (!virtio_scsi_disk_present(i)) {
            continue;
        }
        console_printf("scsi: virtio-scsi disk %u present (%u bytes)\n", (unsigned)i, (unsigned)virtio_scsi_disk_size(i));
    }

    kernel_exit_stack_top = (uint64_t)(uintptr_t)(&post_user_stack[sizeof(post_user_stack)]);

    vm_init();

    gdt_init();
    gdt_set_kernel_stack(kernel_exit_stack_top);
    idt_init();
    enable_user_xsave();
    syscall_init();

    if (userland_run_default_shell() != 0) {
        console_write("No userspace shell could be launched; halting\n");
        kernel_shutdown();
    }

    console_write("userspace launcher returned unexpectedly; halting\n");
    kernel_shutdown();
}
