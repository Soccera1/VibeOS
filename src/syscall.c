#include <stdint.h>
#include <kernel/vfs.h>
#include <kernel/vmm.h>
#include <kernel/debugcon.h>
#include <string.h>
#include <vibeos/syscall.h>

extern void terminal_write(const char* s);
extern void terminal_putc(char c);
extern char keyboard_getc();
extern int elf_load(vfs_node_t *file, uint32_t *entry);
extern void enter_user_mode(uint32_t entry, uint32_t stack);

struct registers {
    uint32_t ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, useresp, ss;
} __attribute__((packed));

void syscall_handler(struct registers *regs) {
    uint32_t syscall_no = regs->eax;

    switch (syscall_no) {
        case SYS_EXIT:
            print_debugcon("User process exited.\n");
            vfs_node_t *sh = finddir_vfs(vfs_root, "sh");
            uint32_t entry;
            if (sh && elf_load(sh, &entry) == 0) {
                enter_user_mode(entry, 0x4FFFF0);
            }
            break;

        case SYS_READ:
            if (regs->ebx == 0) { // stdin
                volatile char *buf = (volatile char*)regs->ecx;
                char c = keyboard_getc();
                buf[0] = c;
                regs->eax = 1; 
            } else {
                regs->eax = 0;
            }
            break;

        case SYS_WRITE:
            if (regs->ebx == 1 || regs->ebx == 2) {
                unsigned char *buf = (unsigned char*)regs->ecx;
                uint32_t len = regs->edx;
                
                for (uint32_t i = 0; i < len; i++) {
                    unsigned char c = buf[i];
                    if (c != 0) {
                        terminal_putc(c);
                    }
                }
                regs->eax = len;
            } else {
                regs->eax = 0;
            }
            break;

        case SYS_EXEC: {
            char *filename = (char*)regs->ebx;
            vfs_node_t *file = finddir_vfs(vfs_root, filename);
            if (file) {
                uint32_t entry;
                if (elf_load(file, &entry) == 0) {
                    regs->eax = 0;
                    enter_user_mode(entry, 0x4FFFF0);
                }
            }
            regs->eax = -1;
            break;
        }

        case SYS_LS: {
            if (vfs_root) {
                int i = 0;
                struct dirent *de;
                while ((de = readdir_vfs(vfs_root, i++))) {
                    terminal_write(de->name);
                    terminal_write("  ");
                }
                terminal_write("\n");
                regs->eax = 0;
            }
            break;
        }

        default:
            regs->eax = -1;
            break;
    }
}