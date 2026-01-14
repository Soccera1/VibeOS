#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <kernel/vfs.h>
#include <kernel/vmm.h>

extern void terminal_write(const char* s);
extern void terminal_putc(char c);
extern void terminal_clear();
extern char keyboard_getc();

extern int elf_load(vfs_node_t *file, uint32_t *entry);

#define MAX_ARGS 16
#define MAX_CMD_LEN 128

static char* argv[MAX_ARGS];
static int argc;

static void enter_user_mode(uint32_t entry, uint32_t stack) {
    asm volatile(
        "cli;"
        "mov $0x23, %%ax;"
        "mov %%ax, %%ds;"
        "mov %%ax, %%es;"
        "mov %%ax, %%fs;"
        "mov %%ax, %%gs;"
        "pushl $0x23;"
        "pushl %0;"
        "pushfl;"
        "popl %%eax;"
        "orl $0x200, %%eax;"
        "pushl %%eax;"
        "pushl $0x1B;"
        "pushl %1;"
        "iret;"
        : : "r"(stack), "r"(entry) : "eax"
    );
}

static void parse_command(char* line) {
    argc = 0;
    char* ptr = line;
    while (*ptr && argc < MAX_ARGS) {
        while (*ptr == ' ') ptr++;
        if (*ptr == '\0') break;

        if (*ptr == '"' || *ptr == '\'') {
            char quote = *ptr++;
            argv[argc++] = ptr;
            while (*ptr && *ptr != quote) ptr++;
            if (*ptr) *ptr++ = '\0';
        } else {
            argv[argc++] = ptr;
            while (*ptr && *ptr != ' ') ptr++;
            if (*ptr) *ptr++ = '\0';
        }
    }
}

void shell_main() {
    char line[MAX_CMD_LEN];
    int line_idx = 0;

    terminal_write("\nVibeOS Shell v0.6 (Exec Enabled)\n");
    terminal_write("Ready.\n\n");

    while (1) {
        terminal_write("sh$ ");
        line_idx = 0;
        
        while (1) {
            char c = keyboard_getc();
            if (c == '\n') {
                terminal_putc('\n');
                line[line_idx] = '\0';
                break;
            } else if (c == '\b') {
                if (line_idx > 0) {
                    line_idx--;
                    terminal_putc('\b');
                }
            } else {
                if (line_idx < MAX_CMD_LEN - 1) {
                    line[line_idx++] = c;
                    terminal_putc(c);
                }
            }
        }

        if (line_idx == 0) continue;

        parse_command(line);
        if (argc == 0) continue;

        char* cmd = argv[0];

        if (strcmp(cmd, "ls") == 0) {
            if (vfs_root) {
                int i = 0;
                struct dirent *de;
                while ((de = readdir_vfs(vfs_root, i++))) {
                    terminal_write(de->name);
                    terminal_write("  ");
                }
                terminal_putc('\n');
            }
        } else if (strcmp(cmd, "exec") == 0) {
            if (argc < 2) {
                terminal_write("Usage: exec <filename>\n");
                continue;
            }
            vfs_node_t *file = finddir_vfs(vfs_root, argv[1]);
            if (file) {
                // Map the program region (0x400000) as USER accessible
                for (uint32_t i = 0; i < 16; i++) {
                    vmm_map(0x400000 + (i * 4096), 0x400000 + (i * 4096), PAGE_PRESENT | PAGE_RW | PAGE_USER);
                }
                // Map the stack region (0x500000) as USER accessible
                vmm_map(0x500000 - 4096, 0x500000 - 4096, PAGE_PRESENT | PAGE_RW | PAGE_USER);

                uint32_t entry;
                if (elf_load(file, &entry) == 0) {
                    terminal_write("Jumping to User Mode...\n");
                    enter_user_mode(entry, 0x500000);
                }
            } else {
                terminal_write("exec: file not found\n");
            }
        } else if (strcmp(cmd, "help") == 0) {
            terminal_write("VibeOS Built-ins: ls, exec, exit, help\n");
        } else {
            terminal_write("sh: ");
            terminal_write(cmd);
            terminal_write(": not found\n");
        }
    }
}