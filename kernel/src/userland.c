#include "userland.h"

#include <stdint.h>

#include "common.h"
#include "console.h"
#include "initramfs.h"
#include "string.h"

#define ELF_MAGIC 0x464C457Fu
#define ET_EXEC 2u
#define PT_LOAD 1u

#define USER_LIMIT 0x3F000000ull
#define USER_STACK_TOP 0x08000000ull

struct elf64_ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

extern void enter_user_mode(uint64_t entry, uint64_t stack_top);

struct user_exec_info {
    uint64_t entry;
    uint64_t phdr;
    uint64_t phent;
    uint64_t phnum;
};

static uint64_t g_user_image_start;
static uint64_t g_user_image_end;

static uint64_t push_bytes(uint64_t sp, const void* data, size_t len) {
    sp -= len;
    memcpy((void*)(uintptr_t)sp, data, len);
    return sp;
}

static uint64_t push_u64(uint64_t sp, uint64_t value) {
    sp -= sizeof(uint64_t);
    *(uint64_t*)(uintptr_t)sp = value;
    return sp;
}

static uint64_t push_auxv(uint64_t sp, uint64_t type, uint64_t value) {
    sp = push_u64(sp, value);
    sp = push_u64(sp, type);
    return sp;
}

static uint64_t build_user_stack(const struct user_exec_info* exec) {
    const char* argv[] = {"busybox", "sh", "-i"};
    const char* envp[] = {
        "TERM=dumb",
        "HOME=/",
        "PATH=/bin:/usr/bin",
        "SH_STANDALONE=1",
        "GLIBC_TUNABLES=glibc.pthread.rseq=0",
    };
    const char* execfn = "/bin/busybox";
    const char* platform = "x86_64";

    uint64_t argv_ptrs[ARRAY_LEN(argv)];
    uint64_t env_ptrs[ARRAY_LEN(envp)];

    uint64_t sp = USER_STACK_TOP;

    uint8_t at_random[16] = {
        0x12, 0x6E, 0xA7, 0x39, 0x55, 0xC8, 0x03, 0xF1, 0x88, 0x22, 0x74, 0xB5, 0xE1, 0x9C, 0x41, 0x0D,
    };

    size_t execfn_len = strlen(execfn) + 1u;
    sp = push_bytes(sp, execfn, execfn_len);
    uint64_t execfn_ptr = sp;

    size_t platform_len = strlen(platform) + 1u;
    sp = push_bytes(sp, platform, platform_len);
    uint64_t platform_ptr = sp;

    sp = push_bytes(sp, at_random, sizeof(at_random));
    uint64_t at_random_ptr = sp;

    for (int i = (int)ARRAY_LEN(envp) - 1; i >= 0; --i) {
        size_t len = strlen(envp[i]) + 1u;
        sp = push_bytes(sp, envp[i], len);
        env_ptrs[i] = sp;
    }

    for (int i = (int)ARRAY_LEN(argv) - 1; i >= 0; --i) {
        size_t len = strlen(argv[i]) + 1u;
        sp = push_bytes(sp, argv[i], len);
        argv_ptrs[i] = sp;
    }

    sp &= ~0x0Full;

    sp = push_auxv(sp, 0, 0);                          // AT_NULL
    sp = push_auxv(sp, 31, execfn_ptr);                // AT_EXECFN
    sp = push_auxv(sp, 51, 2048);                      // AT_MINSIGSTKSZ
    sp = push_auxv(sp, 15, platform_ptr);              // AT_PLATFORM
    sp = push_auxv(sp, 25, at_random_ptr);             // AT_RANDOM
    sp = push_auxv(sp, 16, 0);                         // AT_HWCAP
    sp = push_auxv(sp, 26, 0);                         // AT_HWCAP2
    sp = push_auxv(sp, 33, 0);                         // AT_SYSINFO_EHDR
    sp = push_auxv(sp, 23, 0);                         // AT_SECURE
    sp = push_auxv(sp, 17, 100);                       // AT_CLKTCK
    sp = push_auxv(sp, 8, 0);                          // AT_FLAGS
    sp = push_auxv(sp, 7, 0);                          // AT_BASE
    sp = push_auxv(sp, 14, 0);                         // AT_EGID
    sp = push_auxv(sp, 13, 0);                         // AT_GID
    sp = push_auxv(sp, 12, 0);                         // AT_EUID
    sp = push_auxv(sp, 11, 0);                         // AT_UID
    sp = push_auxv(sp, 9, exec->entry);                // AT_ENTRY
    sp = push_auxv(sp, 6, 4096);                       // AT_PAGESZ
    sp = push_auxv(sp, 5, exec->phnum);                // AT_PHNUM
    sp = push_auxv(sp, 4, exec->phent);                // AT_PHENT
    sp = push_auxv(sp, 3, exec->phdr);                 // AT_PHDR

    sp = push_u64(sp, 0);             // envp terminator
    for (int i = (int)ARRAY_LEN(envp) - 1; i >= 0; --i) {
        sp = push_u64(sp, env_ptrs[i]);
    }

    sp = push_u64(sp, 0);             // argv terminator
    for (int i = (int)ARRAY_LEN(argv) - 1; i >= 0; --i) {
        sp = push_u64(sp, argv_ptrs[i]);
    }

    sp = push_u64(sp, ARRAY_LEN(argv));

    return sp;
}

static int load_elf64_exec(const uint8_t* image, size_t image_size, struct user_exec_info* exec) {
    if (image_size < sizeof(struct elf64_ehdr)) {
        return -1;
    }

    const struct elf64_ehdr* eh = (const struct elf64_ehdr*)image;
    if (*(const uint32_t*)&eh->e_ident[0] != ELF_MAGIC) {
        return -1;
    }
    if (eh->e_type != ET_EXEC) {
        return -1;
    }
    if (eh->e_phentsize != sizeof(struct elf64_phdr)) {
        return -1;
    }

    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr) > image_size) {
        return -1;
    }

    const struct elf64_phdr* ph = (const struct elf64_phdr*)(image + eh->e_phoff);
    uint64_t phdr_vaddr = 0;
    uint64_t image_start = UINT64_MAX;
    uint64_t image_end = 0;

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) {
            continue;
        }

        if (ph[i].p_offset + ph[i].p_filesz > image_size) {
            return -1;
        }
        if (ph[i].p_vaddr + ph[i].p_memsz >= USER_LIMIT) {
            return -1;
        }

        uint8_t* dest = (uint8_t*)(uintptr_t)ph[i].p_vaddr;
        const uint8_t* src = image + ph[i].p_offset;

        memset(dest, 0, (size_t)ph[i].p_memsz);
        memcpy(dest, src, (size_t)ph[i].p_filesz);

        if (eh->e_phoff >= ph[i].p_offset && eh->e_phoff + (uint64_t)sizeof(struct elf64_phdr) <= ph[i].p_offset + ph[i].p_filesz) {
            phdr_vaddr = ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset);
        }

        if (ph[i].p_vaddr < image_start) {
            image_start = ph[i].p_vaddr;
        }
        uint64_t seg_end = ph[i].p_vaddr + ph[i].p_memsz;
        if (seg_end > image_end) {
            image_end = seg_end;
        }
    }

    exec->entry = eh->e_entry;
    exec->phdr = phdr_vaddr;
    exec->phent = eh->e_phentsize;
    exec->phnum = eh->e_phnum;

    if (image_start == UINT64_MAX || image_end <= image_start) {
        return -1;
    }

    image_start &= ~0xFFFull;
    image_end = (image_end + 0xFFFull) & ~0xFFFull;
    g_user_image_start = image_start;
    g_user_image_end = image_end;
    return 0;
}

int userland_run_busybox(void) {
    g_user_image_start = 0;
    g_user_image_end = 0;

    struct initramfs_entry busybox;
    if (initramfs_find("/bin/busybox", &busybox) != 0) {
        console_write("/bin/busybox not found in initramfs\n");
        return -1;
    }

    struct user_exec_info exec;
    if (load_elf64_exec(busybox.data, busybox.size, &exec) != 0) {
        console_write("busybox ELF load failed (need static non-PIE ELF64)\n");
        return -1;
    }

    uint64_t user_stack = build_user_stack(&exec);
    console_write("Launching /bin/busybox sh -i\n");
    enter_user_mode(exec.entry, user_stack);
    return 0;
}

void userland_get_image_span(uint64_t* start_out, uint64_t* end_out) {
    if (start_out != NULL) {
        *start_out = g_user_image_start;
    }
    if (end_out != NULL) {
        *end_out = g_user_image_end;
    }
}

void userland_set_image_span(uint64_t start, uint64_t end) {
    g_user_image_start = start;
    g_user_image_end = end;
}
