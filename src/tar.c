#include <kernel/vfs.h>
#include <string.h>
#include <stdint.h>

struct tar_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
} __attribute__((packed));

static uint32_t get_size(const char *in) {
    uint32_t size = 0;
    uint32_t j;
    uint32_t count = 1;
    for (j = 11; j > 0; j--, count *= 8)
        size += ((in[j - 1] - '0') * count);
    return size;
}

static uint32_t tar_addr;
static vfs_node_t tar_root;
static struct dirent dirent;

static uint32_t tar_read(vfs_node_t *node, uint32_t offset, uint32_t size, uint8_t *buffer) {
    uint32_t file_offset = node->impl;
    memcpy(buffer, (uint8_t*)(tar_addr + file_offset + offset), size);
    return size;
}

static struct dirent *tar_readdir(vfs_node_t *node, uint32_t index) {
    (void)node;
    uint32_t i = 0;
    uint32_t curr = 0;
    while (1) {
        struct tar_header *header = (struct tar_header *)(tar_addr + i);
        if (header->name[0] == '\0') return 0;

        if (curr == index) {
            strcpy(dirent.name, header->name);
            dirent.ino = i;
            return &dirent;
        }

        uint32_t size = get_size(header->size);
        i += ((size / 512) + 1) * 512;
        if (size % 512) i += 512;
        curr++;
    }
}

static vfs_node_t *tar_finddir(vfs_node_t *node, char *name) {
    if (strcmp(name, "/") == 0 || strcmp(name, ".") == 0 || strcmp(name, "") == 0) return node;
    if (name[0] == '/') name++;
    uint32_t i = 0;
    static vfs_node_t res;
    while (1) {
        struct tar_header *header = (struct tar_header *)(tar_addr + i);
        if (header->name[0] == '\0') return 0;

        if (strcmp(header->name, name) == 0 || 
           (header->name[0] == '.' && header->name[1] == '/' && strcmp(header->name + 2, name) == 0)) {
            strcpy(res.name, name);
            res.length = get_size(header->size);
            res.impl = i + 512; // Data starts after header
            res.flags = VFS_FILE;
            res.read = tar_read;
            return &res;
        }

        uint32_t size = get_size(header->size);
        i += ((size / 512) + 1) * 512;
        if (size % 512) i += 512;
    }
}

void tar_init(uint32_t addr) {
    tar_addr = addr;
    strcpy(tar_root.name, "/");
    tar_root.flags = VFS_DIRECTORY;
    tar_root.readdir = tar_readdir;
    tar_root.finddir = tar_finddir;
    vfs_root = &tar_root;
}
