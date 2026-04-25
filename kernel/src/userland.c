#include "userland.h"

#include <stdint.h>

#include "common.h"
#include "console.h"
#include "fs.h"
#include "initramfs.h"
#include "kmalloc.h"
#include "process.h"
#include "string.h"
#include "vm.h"

#define ELF_MAGIC 0x464C457Fu
#define ET_EXEC 2u
#define ET_DYN 3u
#define PF_X 0x1u
#define PF_W 0x2u
#define PF_R 0x4u
#define PT_LOAD 1u
#define PT_INTERP 3u
#define USER_ET_DYN_BASE 0x01000000ull
#define USER_INTERP_BASE 0x03000000ull
#define USER_INTERP_GAP 0x00100000ull

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
    uint64_t start;
    uint64_t base;
    uint64_t phdr;
    uint64_t phent;
    uint64_t phnum;
    uint64_t image_start;
    uint64_t image_end;
    uint64_t load_bias;
    bool has_interp;
    char interp_path[FS_MAX_PATH];
};

static uint64_t g_user_image_start;
static uint64_t g_user_image_end;

static uint64_t push_bytes(uint64_t sp, const void* data, size_t len, struct vm_space* space) {
    sp -= len;
    (void)vm_space_write(space, sp, data, len);
    return sp;
}

static uint64_t push_u64(uint64_t sp, uint64_t value, struct vm_space* space) {
    sp -= sizeof(uint64_t);
    (void)vm_space_write(space, sp, &value, sizeof(value));
    return sp;
}

static uint64_t push_auxv(uint64_t sp, uint64_t type, uint64_t value, struct vm_space* space) {
    sp = push_u64(sp, value, space);
    sp = push_u64(sp, type, space);
    return sp;
}

static uint64_t page_align_down(uint64_t value) {
    return value & VM_PAGE_MASK;
}

static uint64_t page_align_up(uint64_t value) {
    return (value + VM_PAGE_SIZE - 1ull) & VM_PAGE_MASK;
}

static uint64_t choose_interp_base(uint64_t main_image_end) {
    uint64_t base = page_align_up(main_image_end + USER_INTERP_GAP);
    if (base < USER_INTERP_BASE) {
        base = USER_INTERP_BASE;
    }
    return base;
}

static uint32_t elf_segment_prot(uint32_t flags) {
    uint32_t prot = VM_PROT_NONE;
    if ((flags & PF_R) != 0u) {
        prot |= VM_PROT_READ;
    }
    if ((flags & PF_W) != 0u) {
        prot |= VM_PROT_READ | VM_PROT_WRITE;
    }
    if ((flags & PF_X) != 0u) {
        prot |= VM_PROT_EXEC;
    }
    return prot;
}

static uint64_t build_user_stack(const struct user_exec_info* exec, const char* execfn,
                                 const char* const* argv, size_t argc, struct vm_space* space) {
    const char* envp[] = {
        "TERM=ansi",
        "HOME=/",
        "PATH=/bin:/sbin:/usr/bin",
        "SH_STANDALONE=1",
        "GLIBC_TUNABLES=glibc.pthread.rseq=0",
    };
    const char* platform = "x86_64";

    uint64_t argv_ptrs[8];
    uint64_t env_ptrs[ARRAY_LEN(envp)];

    uint64_t sp = VM_USER_STACK_TOP;

    uint8_t at_random[16] = {
        0x12, 0x6E, 0xA7, 0x39, 0x55, 0xC8, 0x03, 0xF1, 0x88, 0x22, 0x74, 0xB5, 0xE1, 0x9C, 0x41, 0x0D,
    };

    (void)vm_space_map_zero(space, VM_USER_STACK_BASE, VM_USER_STACK_SIZE, VM_PROT_READ | VM_PROT_WRITE);

    size_t execfn_len = strlen(execfn) + 1u;
    sp = push_bytes(sp, execfn, execfn_len, space);
    uint64_t execfn_ptr = sp;

    size_t platform_len = strlen(platform) + 1u;
    sp = push_bytes(sp, platform, platform_len, space);
    uint64_t platform_ptr = sp;

    sp = push_bytes(sp, at_random, sizeof(at_random), space);
    uint64_t at_random_ptr = sp;

    for (int i = (int)ARRAY_LEN(envp) - 1; i >= 0; --i) {
        size_t len = strlen(envp[i]) + 1u;
        sp = push_bytes(sp, envp[i], len, space);
        env_ptrs[i] = sp;
    }

    if (argc > ARRAY_LEN(argv_ptrs)) {
        argc = ARRAY_LEN(argv_ptrs);
    }

    for (int i = (int)argc - 1; i >= 0; --i) {
        size_t len = strlen(argv[i]) + 1u;
        sp = push_bytes(sp, argv[i], len, space);
        argv_ptrs[i] = sp;
    }

    sp &= ~0x0Full;

    sp = push_auxv(sp, 0, 0, space);                          // AT_NULL
    sp = push_auxv(sp, 31, execfn_ptr, space);                // AT_EXECFN
    sp = push_auxv(sp, 51, 2048, space);                      // AT_MINSIGSTKSZ
    sp = push_auxv(sp, 15, platform_ptr, space);              // AT_PLATFORM
    sp = push_auxv(sp, 25, at_random_ptr, space);             // AT_RANDOM
    sp = push_auxv(sp, 16, 0, space);                         // AT_HWCAP
    sp = push_auxv(sp, 26, 0, space);                         // AT_HWCAP2
    sp = push_auxv(sp, 33, 0, space);                         // AT_SYSINFO_EHDR
    sp = push_auxv(sp, 23, 0, space);                         // AT_SECURE
    sp = push_auxv(sp, 17, 100, space);                       // AT_CLKTCK
    sp = push_auxv(sp, 8, 0, space);                          // AT_FLAGS
    sp = push_auxv(sp, 7, exec->base, space);                 // AT_BASE
    sp = push_auxv(sp, 14, 0, space);                         // AT_EGID
    sp = push_auxv(sp, 13, 0, space);                         // AT_GID
    sp = push_auxv(sp, 12, 0, space);                         // AT_EUID
    sp = push_auxv(sp, 11, 0, space);                         // AT_UID
    sp = push_auxv(sp, 9, exec->entry, space);                // AT_ENTRY
    sp = push_auxv(sp, 6, 4096, space);                       // AT_PAGESZ
    sp = push_auxv(sp, 5, exec->phnum, space);                // AT_PHNUM
    sp = push_auxv(sp, 4, exec->phent, space);                // AT_PHENT
    sp = push_auxv(sp, 3, exec->phdr, space);                 // AT_PHDR

    sp = push_u64(sp, 0, space);             // envp terminator
    for (int i = (int)ARRAY_LEN(envp) - 1; i >= 0; --i) {
        sp = push_u64(sp, env_ptrs[i], space);
    }

    sp = push_u64(sp, 0, space);             // argv terminator
    for (int i = (int)argc - 1; i >= 0; --i) {
        sp = push_u64(sp, argv_ptrs[i], space);
    }

    sp = push_u64(sp, argc, space);

    return sp;
}

static int load_elf64_exec(const uint8_t* image, size_t image_size, uint64_t et_dyn_base, struct user_exec_info* exec,
                           struct vm_space* space) {
    if (image_size < sizeof(struct elf64_ehdr)) {
        return -1;
    }

    memset(exec, 0, sizeof(*exec));

    const struct elf64_ehdr* eh = (const struct elf64_ehdr*)image;
    if (*(const uint32_t*)&eh->e_ident[0] != ELF_MAGIC) {
        return -1;
    }
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) {
        return -1;
    }
    if (eh->e_phentsize != sizeof(struct elf64_phdr)) {
        return -1;
    }

    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr) > image_size) {
        return -1;
    }

    const struct elf64_phdr* ph = (const struct elf64_phdr*)(image + eh->e_phoff);
    uint64_t phdr_table_size = (uint64_t)eh->e_phnum * eh->e_phentsize;
    uint64_t phdr_vaddr = 0;
    uint64_t image_start = UINT64_MAX;
    uint64_t image_end = 0;
    uint64_t min_load_vaddr = UINT64_MAX;
    uint64_t max_load_vaddr = 0;

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_INTERP) {
            if (exec->has_interp || ph[i].p_filesz == 0 || ph[i].p_filesz > FS_MAX_PATH ||
                ph[i].p_offset + ph[i].p_filesz > image_size) {
                return -1;
            }

            const char* src = (const char*)(image + ph[i].p_offset);
            bool terminated = false;
            for (size_t j = 0; j < (size_t)ph[i].p_filesz; ++j) {
                exec->interp_path[j] = src[j];
                if (src[j] == '\0') {
                    terminated = true;
                    break;
                }
            }
            if (!terminated) {
                return -1;
            }
            exec->has_interp = true;
            continue;
        }

        if (ph[i].p_type != PT_LOAD) {
            continue;
        }
        if (ph[i].p_offset + ph[i].p_filesz > image_size) {
            return -1;
        }

        uint64_t seg_start = page_align_down(ph[i].p_vaddr);
        uint64_t seg_end = page_align_up(ph[i].p_vaddr + ph[i].p_memsz);
        if (seg_start < min_load_vaddr) {
            min_load_vaddr = seg_start;
        }
        if (seg_end > max_load_vaddr) {
            max_load_vaddr = seg_end;
        }
    }

    if (min_load_vaddr == UINT64_MAX || max_load_vaddr <= min_load_vaddr) {
        return -1;
    }

    uint64_t load_bias = 0;
    if (eh->e_type == ET_DYN) {
        uint64_t load_base = (et_dyn_base != 0) ? page_align_down(et_dyn_base) : USER_ET_DYN_BASE;
        if (load_base < min_load_vaddr) {
            return -1;
        }
        load_bias = load_base - min_load_vaddr;
    }

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) {
            continue;
        }

        if (ph[i].p_offset + ph[i].p_filesz > image_size) {
            return -1;
        }
        uint64_t seg_vaddr = ph[i].p_vaddr + load_bias;
        if (seg_vaddr + ph[i].p_memsz >= VM_USER_ELF_LIMIT) {
            return -1;
        }

        const uint8_t* src = image + ph[i].p_offset;
        if (vm_space_map_zero(space, seg_vaddr, (size_t)ph[i].p_memsz, elf_segment_prot(ph[i].p_flags)) != 0) {
            return -1;
        }
        if (vm_space_write(space, seg_vaddr, src, (size_t)ph[i].p_filesz) != 0) {
            return -1;
        }

        if (eh->e_phoff >= ph[i].p_offset && eh->e_phoff + phdr_table_size <= ph[i].p_offset + ph[i].p_filesz) {
            phdr_vaddr = seg_vaddr + (eh->e_phoff - ph[i].p_offset);
        }

        if (seg_vaddr < image_start) {
            image_start = seg_vaddr;
        }
        uint64_t seg_end = seg_vaddr + ph[i].p_memsz;
        if (seg_end > image_end) {
            image_end = seg_end;
        }
    }

    exec->entry = eh->e_entry + load_bias;
    exec->start = exec->entry;
    exec->base = 0;
    if (image_start == UINT64_MAX || image_end <= image_start) {
        return -1;
    }

    image_start = page_align_down(image_start);
    image_end = page_align_up(image_end);
    exec->phdr = phdr_vaddr;
    exec->phent = eh->e_phentsize;
    exec->phnum = eh->e_phnum;
    exec->image_start = image_start;
    exec->image_end = image_end;
    exec->load_bias = load_bias;
    g_user_image_start = image_start;
    g_user_image_end = image_end;
    return 0;
}

static int userland_run_program(const char* path, const char* const* argv, size_t argc,
                                const char* launch_message, const char* missing_message,
                                const char* load_failed_message);

static int userland_run_program(const char* path, const char* const* argv, size_t argc,
                                const char* launch_message, const char* missing_message,
                                const char* load_failed_message) {
    g_user_image_start = 0;
    g_user_image_end = 0;

    struct fs_entry program;
    if (fs_lookup(path, &program) != 0 || (program.mode & FS_S_IFMT) != FS_S_IFREG) {
        console_write(missing_message);
        return -1;
    }

    uint8_t* image = kmalloc(program.size);
    if (image == NULL) {
        console_write("kernel out of memory while loading userspace image\n");
        return -1;
    }

    int rr = fs_read(&program, 0, image, program.size);
    if (rr < 0 || (size_t)rr != program.size) {
        kfree(image);
        console_write(load_failed_message);
        return -1;
    }

    struct process* current = process_current();
    if (current == NULL) {
        kfree(image);
        return -1;
    }

    struct vm_space next_vm;
    if (vm_space_init(&next_vm) != 0) {
        kfree(image);
        console_write("kernel out of memory while preparing userspace vm\n");
        return -1;
    }

    struct user_exec_info exec;
    if (load_elf64_exec(image, program.size, 0, &exec, &next_vm) != 0) {
        vm_space_destroy(&next_vm);
        kfree(image);
        console_write(load_failed_message);
        return -1;
    }

    struct user_exec_info interp_exec;
    memset(&interp_exec, 0, sizeof(interp_exec));
    if (exec.has_interp) {
        struct fs_entry interp_entry;
        if (fs_lookup(exec.interp_path, &interp_entry) != 0 || (interp_entry.mode & FS_S_IFMT) != FS_S_IFREG) {
            vm_space_destroy(&next_vm);
            kfree(image);
            console_write(load_failed_message);
            return -1;
        }

        uint8_t* interp = kmalloc(interp_entry.size);
        if (interp == NULL) {
            vm_space_destroy(&next_vm);
            kfree(image);
            console_write("kernel out of memory while loading userspace interpreter\n");
            return -1;
        }

        int interp_rr = fs_read(&interp_entry, 0, interp, interp_entry.size);
        if (interp_rr < 0 || (size_t)interp_rr != interp_entry.size ||
            load_elf64_exec(interp, interp_entry.size, choose_interp_base(g_user_image_end), &interp_exec, &next_vm) != 0) {
            vm_space_destroy(&next_vm);
            kfree(interp);
            kfree(image);
            console_write(load_failed_message);
            return -1;
        }
        kfree(interp);

        exec.start = interp_exec.entry;
        exec.base = interp_exec.load_bias;
        if (interp_exec.image_start < g_user_image_start) {
            g_user_image_start = interp_exec.image_start;
        }
        if (interp_exec.image_end > g_user_image_end) {
            g_user_image_end = interp_exec.image_end;
        }
    }
    kfree(image);

    uint64_t user_stack = build_user_stack(&exec, path, argv, argc, &next_vm);
    vm_space_destroy(&current->vm);
    current->vm = next_vm;
    console_write(launch_message);
    vm_space_activate(&current->vm);
    enter_user_mode(exec.start, user_stack);
    return 0;
}

int userland_run_default_shell(void) {
    static const char* const init_argv[] = {"busybox", "sh", "/init"};
    static const char* const bash_argv[] = {"bash", "-i"};
    static const char* const busybox_argv[] = {"busybox", "sh", "-i"};

    if (userland_run_program("/bin/busybox", init_argv, ARRAY_LEN(init_argv),
                             "Launching /bin/busybox sh /init\n",
                             "/bin/busybox not found in initramfs\n",
                             "init shell launcher load failed\n") == 0) {
        return 0;
    }

    if (userland_run_program("/usr/bin/bash", bash_argv, ARRAY_LEN(bash_argv),
                             "Falling back to /usr/bin/bash -i\n",
                             "/usr/bin/bash not found\n",
                             "bash ELF load failed\n") == 0) {
        return 0;
    }

    return userland_run_program("/bin/busybox", busybox_argv, ARRAY_LEN(busybox_argv),
                                "Falling back to /bin/busybox sh -i\n",
                                "/bin/busybox not found in initramfs\n",
                                "busybox ELF load failed\n");
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
