#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "console.h"
#include "gdt.h"
#include "idt.h"
#include "input.h"
#include "initramfs.h"
#include "multiboot2.h"
#include "io.h"
#include "string.h"
#include "syscall.h"
#include "userland.h"

uint64_t kernel_exit_stack_top;

static uint8_t post_user_stack[65536];
static char shell_ls_names[256][64];

static void kernel_shell(void) __attribute__((noreturn));

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

static void read_line(char* out, size_t out_len) {
    size_t n = 0;
    while (n + 1 < out_len) {
        int c = input_read_char_blocking();
        if (c == '\r') {
            c = '\n';
        }

        if (c == '\b') {
            if (n > 0) {
                --n;
                console_putc('\b');
            }
            continue;
        }

        if (c == '\n') {
            console_putc('\n');
            break;
        }

        out[n++] = (char)c;
        console_putc((char)c);
    }
    out[n] = '\0';
}

static const char* trim_left(const char* s) {
    while (*s == ' ' || *s == '\t') {
        ++s;
    }
    return s;
}

static void split_cmd(const char* line, char* cmd, size_t cmd_len, char* arg, size_t arg_len) {
    const char* s = trim_left(line);

    size_t i = 0;
    while (s[i] != '\0' && s[i] != ' ' && s[i] != '\t' && i + 1 < cmd_len) {
        cmd[i] = s[i];
        ++i;
    }
    cmd[i] = '\0';

    while (s[i] == ' ' || s[i] == '\t') {
        ++i;
    }

    size_t j = 0;
    while (s[i] != '\0' && j + 1 < arg_len) {
        arg[j++] = s[i++];
    }
    arg[j] = '\0';
}

static bool top_level_child(const char* dir, const char* full, char* out, size_t out_len) {
    if (strcmp(full, "/") == 0) {
        return false;
    }

    const char* rest = NULL;
    size_t dir_len = strlen(dir);

    if (strcmp(dir, "/") == 0) {
        if (full[0] != '/' || full[1] == '\0') {
            return false;
        }
        rest = full + 1;
    } else {
        if (strncmp(full, dir, dir_len) != 0 || full[dir_len] != '/') {
            return false;
        }
        rest = full + dir_len + 1;
    }

    if (*rest == '\0') {
        return false;
    }

    size_t i = 0;
    while (rest[i] != '\0' && rest[i] != '/' && i + 1 < out_len) {
        out[i] = rest[i];
        ++i;
    }
    out[i] = '\0';
    return i > 0;
}

static bool seen_name(char names[256][64], size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return true;
        }
    }
    return false;
}

static void shell_ls(const char* path) {
    const char* dir = (path[0] == '\0') ? "/" : path;

    if (strcmp(dir, "/") != 0 && dir[0] != '/') {
        console_write("ls: use absolute path\n");
        return;
    }

    size_t count = 0;

    for (size_t i = 0; i < initramfs_entry_count(); ++i) {
        const struct initramfs_entry* e = initramfs_entry_at(i);
        if (e == NULL) {
            continue;
        }
        char child[64];
        if (!top_level_child(dir, e->path, child, sizeof(child))) {
            continue;
        }
        if (seen_name(shell_ls_names, count, child)) {
            continue;
        }
        if (count >= ARRAY_LEN(shell_ls_names)) {
            break;
        }
        strncpy(shell_ls_names[count], child, sizeof(shell_ls_names[count]));
        shell_ls_names[count][sizeof(shell_ls_names[count]) - 1] = '\0';
        ++count;
    }

    if (count == 0) {
        console_write("(empty)\n");
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        console_write(shell_ls_names[i]);
        console_putc('\n');
    }
}

static void shell_cat(const char* path) {
    if (path[0] == '\0') {
        console_write("cat: missing file\n");
        return;
    }

    struct initramfs_entry e;
    if (initramfs_find(path, &e) != 0) {
        console_write("cat: not found\n");
        return;
    }

    for (size_t i = 0; i < e.size; ++i) {
        console_putc((char)e.data[i]);
    }
    if (e.size == 0 || e.data[e.size - 1] != '\n') {
        console_putc('\n');
    }
}

static void kernel_shell(void) {
    char line[256];
    char cmd[64];
    char arg[192];

    for (;;) {
        console_write("vibeos# ");
        read_line(line, sizeof(line));
        split_cmd(line, cmd, sizeof(cmd), arg, sizeof(arg));

        if (cmd[0] == '\0') {
            continue;
        }
        if (strcmp(cmd, "help") == 0) {
            console_write("help, clear, ls [path], cat <path>, busybox\n");
            continue;
        }
        if (strcmp(cmd, "clear") == 0) {
            console_clear();
            continue;
        }
        if (strcmp(cmd, "ls") == 0) {
            shell_ls(arg);
            continue;
        }
        if (strcmp(cmd, "cat") == 0) {
            shell_cat(arg);
            continue;
        }
        if (strcmp(cmd, "busybox") == 0) {
            if (userland_run_busybox() != 0) {
                console_write("busybox launch failed\n");
            }
            continue;
        }

        console_write("unknown command\n");
    }
}

void userland_exit_handler(uint64_t code) {
    console_printf("\n[userland exited: %u]\n", code);
    kernel_shell();
}

void kernel_main(uint64_t mb2_info) {
    console_init();
    console_write("VibeOS amd64 monolithic kernel prototype\n");

    const struct mb2_tag_module* module = mb2_find_first_module(mb2_info);
    if (module == NULL) {
        console_write("No initramfs module provided by bootloader\n");
    } else {
        const uint8_t* start = (const uint8_t*)(uintptr_t)module->mod_start;
        size_t size = (size_t)(module->mod_end - module->mod_start);
        initramfs_init(start, size);
        console_printf("initramfs: %u bytes, %u entries\n", (unsigned)size, (unsigned)initramfs_entry_count());
    }

    kernel_exit_stack_top = (uint64_t)(uintptr_t)(&post_user_stack[sizeof(post_user_stack)]);

    gdt_init();
    gdt_set_kernel_stack(kernel_exit_stack_top);
    idt_init();
    enable_user_xsave();
    syscall_init();

    if (userland_run_busybox() != 0) {
        console_write("Falling back to kernel shell\n");
        kernel_shell();
    }

    kernel_shell();
}
