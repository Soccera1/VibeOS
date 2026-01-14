#include <kernel/vfs.h>
#include <kernel/vmm.h>
#include <string.h>
#include <stdint.h>
#include <kernel/debugcon.h>

#define ELF_MAGIC 0x464C457F

typedef struct {
    uint32_t magic;
    uint8_t  elf[12];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf_header_t;

typedef struct {
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
} elf_ph_t;

int elf_load(vfs_node_t *file, uint32_t *entry_out) {
    elf_header_t header;
    read_vfs(file, 0, sizeof(elf_header_t), (uint8_t*)&header);

    if (header.magic != ELF_MAGIC) {
        print_debugcon("ELF: Invalid Magic: 0x");
        print_hex_debugcon(header.magic);
        print_debugcon("\n");
        return -1;
    }

    for (int i = 0; i < header.phnum; i++) {
        elf_ph_t ph;
        read_vfs(file, header.phoff + (i * header.phentsize), sizeof(elf_ph_t), (uint8_t*)&ph);

        if (ph.type == 1) { // PT_LOAD
            print_debugcon("ELF: Mapping segment 0x");
            print_hex_debugcon(ph.vaddr);
            print_debugcon(" size 0x");
            print_hex_debugcon(ph.memsz);
            print_debugcon("\n");

            // Map the range as USER/RW
            uint32_t start_page = ph.vaddr & 0xFFFFF000;
            uint32_t end_page = (ph.vaddr + ph.memsz + PAGE_SIZE - 1) & 0xFFFFF000;
            
            for (uint32_t addr = start_page; addr < end_page; addr += PAGE_SIZE) {
                // Identity map for simplicity since we don't have a heap/allocator yet
                vmm_map(addr, addr, PAGE_PRESENT | PAGE_RW | PAGE_USER);
            }

            // Load the data
            read_vfs(file, ph.offset, ph.filesz, (uint8_t*)ph.vaddr);
            
            // Zero out any BSS section
            if (ph.memsz > ph.filesz) {
                memset((void*)(ph.vaddr + ph.filesz), 0, ph.memsz - ph.filesz);
            }
        }
    }

    *entry_out = header.entry;
    return 0;
}
