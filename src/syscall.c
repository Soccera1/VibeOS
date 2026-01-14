#include <stdint.h>
#include <kernel/vfs.h>
#include <kernel/vmm.h>
#include <kernel/pmm.h>
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

#define MAX_FDS 32
struct fd {
    vfs_node_t *node;
    uint32_t offset;
};

static struct fd fd_table[MAX_FDS];
static uint32_t current_brk = 0x600000;

void syscall_handler(struct registers *regs) {
    uint32_t syscall_no = regs->eax;

    switch (syscall_no) {
        case SYS_EXIT:
            print_debugcon("User process exited.\n");
            vfs_node_t *sh = finddir_vfs(vfs_root, "sh");
            uint32_t entry;
            if (sh && elf_load(sh, &entry) == 0) {
                uint32_t stack_top = 0x500000;
                char* sh_str = (char*)(stack_top - 64);
                strcpy(sh_str, "sh");
                uint32_t* stack = (uint32_t*)(stack_top - 128);
                stack[0] = 1;
                stack[1] = (uint32_t)sh_str;
                stack[2] = 0;
                enter_user_mode(entry, (uint32_t)stack);
            }
            break;

        case SYS_READ: {
            int fd = regs->ebx;
            void *buf = (void*)regs->ecx;
            uint32_t len = regs->edx;

            if (fd == 0) { // stdin
                char *cbuf = (char*)buf;
                for (uint32_t i = 0; i < len; i++) {
                    cbuf[i] = keyboard_getc();
                    if (cbuf[i] == '\n' || cbuf[i] == '\r') {
                        regs->eax = i + 1;
                        return;
                    }
                }
                regs->eax = len;
            } else if (fd >= 0 && fd < MAX_FDS && fd_table[fd].node) {
                uint32_t read = read_vfs(fd_table[fd].node, fd_table[fd].offset, len, (uint8_t*)buf);
                fd_table[fd].offset += read;
                regs->eax = read;
            } else {
                regs->eax = -1;
            }
            break;
        }

        case SYS_WRITE: {
            int fd = regs->ebx;
            void *buf = (void*)regs->ecx;
            uint32_t len = regs->edx;

            if (fd == 1 || fd == 2) { // stdout/stderr
                unsigned char *cbuf = (unsigned char*)buf;
                for (uint32_t i = 0; i < len; i++) {
                    terminal_putc(cbuf[i]);
                }
                regs->eax = len;
            } else if (fd >= 0 && fd < MAX_FDS && fd_table[fd].node) {
                uint32_t written = write_vfs(fd_table[fd].node, fd_table[fd].offset, len, (uint8_t*)buf);
                fd_table[fd].offset += written;
                regs->eax = written;
            } else {
                regs->eax = -1;
            }
            break;
        }

        case SYS_OPEN: {
            char *filename = (char*)regs->ebx;
            vfs_node_t *node = finddir_vfs(vfs_root, filename);
            if (!node) {
                regs->eax = -1;
                break;
            }
            int fd = -1;
            for (int i = 3; i < MAX_FDS; i++) {
                if (!fd_table[i].node) {
                    fd = i;
                    break;
                }
            }
            if (fd != -1) {
                fd_table[fd].node = node;
                fd_table[fd].offset = 0;
                open_vfs(node);
                regs->eax = fd;
            } else {
                regs->eax = -1;
            }
            break;
        }

        case SYS_CLOSE: {
            int fd = regs->ebx;
            if (fd >= 3 && fd < MAX_FDS && fd_table[fd].node) {
                close_vfs(fd_table[fd].node);
                fd_table[fd].node = 0;
                regs->eax = 0;
            } else {
                regs->eax = -1;
            }
            break;
        }

        case SYS_LSEEK: {
            int fd = regs->ebx;
            int offset = regs->ecx;
            int whence = regs->edx;
            if (fd >= 0 && fd < MAX_FDS && fd_table[fd].node) {
                if (whence == 0) fd_table[fd].offset = offset; // SEEK_SET
                else if (whence == 1) fd_table[fd].offset += offset; // SEEK_CUR
                else if (whence == 2) fd_table[fd].offset = fd_table[fd].node->length + offset; // SEEK_END
                regs->eax = fd_table[fd].offset;
            } else {
                regs->eax = -1;
            }
            break;
        }

        case SYS_STAT: {
            char *filename = (char*)regs->ebx;
            struct vfs_node *node = finddir_vfs(vfs_root, filename);
            if (node) {
                struct { uint32_t st_dev; uint32_t st_ino; uint32_t st_mode; uint32_t st_nlink; uint32_t st_uid; uint32_t st_gid; uint32_t st_rdev; uint32_t st_size; } *st = (void*)regs->ecx;
                st->st_size = node->length;
                st->st_mode = node->flags; // Simplified
                regs->eax = 0;
            } else {
                regs->eax = -1;
            }
            break;
        }

        case SYS_BRK: {
            uint32_t new_brk = regs->ebx;
            if (new_brk == 0) {
                regs->eax = current_brk;
            } else {
                while (new_brk > current_brk) {
                    uint32_t phys = pmm_alloc_page();
                    vmm_map(current_brk, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER);
                    current_brk += 4096;
                }
                regs->eax = current_brk;
            }
            break;
        }

        case SYS_EXEC: {
            char *filename = (char*)regs->ebx;
            vfs_node_t *file = finddir_vfs(vfs_root, filename);
            if (file) {
                uint32_t entry;
                if (elf_load(file, &entry) == 0) {
                    // Reset FDs for simplicity
                    for(int i=3; i<MAX_FDS; i++) fd_table[i].node = 0;
                    current_brk = 0x600000;
                    
                    uint32_t stack_top = 0x500000;
                    char* sh_str = (char*)(stack_top - 64);
                    strncpy(sh_str, filename, 63);
                    uint32_t* stack = (uint32_t*)(stack_top - 128);
                    stack[0] = 1;
                    stack[1] = (uint32_t)sh_str;
                    stack[2] = 0;

                    regs->eax = 0;
                    enter_user_mode(entry, (uint32_t)stack);
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