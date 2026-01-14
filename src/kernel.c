#include <kernel/multiboot.h>
#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/vmm.h>
#include <kernel/vfs.h>
#include <kernel/debugcon.h>
#include <stdint.h> 

extern void pic_remap(int offset1, int offset2);
extern void keyboard_init();
extern void terminal_init(uint32_t* addr, uint32_t w, uint32_t h, uint32_t p);
extern void tar_init(uint32_t addr);
extern int elf_load(vfs_node_t *file, uint32_t *entry);
extern void enter_user_mode(uint32_t entry, uint32_t stack);

void kernel_main(uint32_t magic, struct multiboot_info* mbi) {
    print_debugcon("VibeOS Kernel Starting...\n");

    gdt_init();
    set_kernel_stack(0x90000);
    idt_init();
    pic_remap(0x20, 0x28);
    keyboard_init();
    
    if (magic != 0x2BADB002 || !(mbi->flags & (1 << 12))) {
        print_debugcon("Critical Error: Boot info missing\n");
        return;
    }

    uint32_t fb_addr = mbi->framebuffer_addr_lo;
    uint32_t fb_size = mbi->framebuffer_height * mbi->framebuffer_pitch;

    terminal_init((uint32_t*)fb_addr, 
                  mbi->framebuffer_width, 
                  mbi->framebuffer_height, 
                  mbi->framebuffer_pitch);

    uint32_t initrd_addr = 0;
    uint32_t initrd_size = 0;
    if (mbi->flags & (1 << 3) && mbi->mods_count > 0) {
        multiboot_module_t* mod = (multiboot_module_t*)mbi->mods_addr;
        initrd_addr = mod->mod_start;
        initrd_size = mod->mod_end - mod->mod_start;
    }

    vmm_init(fb_addr, fb_size, initrd_addr, initrd_size);

    if (initrd_size > 0) {
        tar_init(initrd_addr);
        print_debugcon("VFS OK\n");
    }

    print_debugcon("Ready. Transitioning to User Mode (sh)...");
    asm volatile("sti");

    vfs_node_t *sh_file = finddir_vfs(vfs_root, "sh");
    if (sh_file) {
        uint32_t entry;
        if (elf_load(sh_file, &entry) == 0) {
            // Map 16KB for User Stack
            uint32_t stack_top = 0x500000;
            for (uint32_t i = 0; i < 4; i++) {
                vmm_map(stack_top - (i+1)*4096, stack_top - (i+1)*4096, PAGE_PRESENT | PAGE_RW | PAGE_USER);
            }
            // Use 0x4FFFF0 to ensure we aren't exactly on the boundary
            enter_user_mode(entry, 0x4FFFF0);
        }
    }

    print_debugcon("Error: Failed to load shell\n");
    while(1) asm volatile("hlt");
}