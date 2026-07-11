#include "userland.h"

#include <stdint.h>

#include "common.h"
#include "console.h"
#include "elf_loader.h"
#include "fs.h"
#include "initramfs.h"
#include "kmalloc.h"
#include "process.h"
#include "syscall.h"
#include "string.h"
#include "vm.h"

#define USER_INTERP_BASE 0x03000000ull
#define USER_INTERP_GAP 0x00100000ull

extern void enter_user_mode(uint64_t entry, uint64_t stack_top);

struct user_exec_info {
    uint64_t start;
    uint64_t base;
    struct elf_image_info image;
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

static uint64_t build_user_stack(const struct user_exec_info* exec, const char* execfn,
                                 const char* const* argv, size_t argc, struct vm_space* space) {
    const char* envp[] = {
        "TERM=vibeos",
        "HOME=/root",
        "USER=root",
        "LOGNAME=root",
        "SHELL=/bin/sh",
        "PATH=/bin:/sbin:/usr/bin",
        "SH_STANDALONE=1",
        "GLIBC_TUNABLES=glibc.pthread.rseq=0",
    };
    const char* platform = "x86_64";

    uint64_t argv_ptrs[8];
    uint64_t env_ptrs[ARRAY_LEN(envp)];

    uint64_t sp = VM_USER_STACK_TOP;

    uint8_t at_random[16];
    syscall_random_bytes(at_random, sizeof(at_random));

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

    const uint64_t auxv_bytes = 21u * 2u * sizeof(uint64_t);
    const uint64_t vectors_bytes = (uint64_t)(ARRAY_LEN(envp) + argc + 3u) * sizeof(uint64_t);
    const uint64_t table_bytes = auxv_bytes + vectors_bytes;
    sp = ((sp - table_bytes) & ~0x0Full) + table_bytes;

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
    sp = push_auxv(sp, 9, exec->image.entry, space);          // AT_ENTRY
    sp = push_auxv(sp, 6, 4096, space);                       // AT_PAGESZ
    sp = push_auxv(sp, 5, exec->image.phnum, space);          // AT_PHNUM
    sp = push_auxv(sp, 4, exec->image.phent, space);          // AT_PHENT
    sp = push_auxv(sp, 3, exec->image.phdr, space);           // AT_PHDR

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
    memset(&exec, 0, sizeof(exec));
    if (elf_load_image(&next_vm, image, program.size, 0, &exec.image) != ELF_LOAD_OK) {
        vm_space_destroy(&next_vm);
        kfree(image);
        console_write(load_failed_message);
        return -1;
    }
    exec.start = exec.image.entry;
    g_user_image_start = exec.image.image_start;
    g_user_image_end = exec.image.image_end;

    struct elf_image_info interp_exec;
    memset(&interp_exec, 0, sizeof(interp_exec));
    if (exec.image.has_interp) {
        struct fs_entry interp_entry;
        if (fs_lookup(exec.image.interp_path, &interp_entry) != 0 || (interp_entry.mode & FS_S_IFMT) != FS_S_IFREG) {
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
            elf_load_image(&next_vm, interp, interp_entry.size, choose_interp_base(g_user_image_end), &interp_exec) != ELF_LOAD_OK ||
            interp_exec.type != ELF_ET_DYN || interp_exec.has_interp) {
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
