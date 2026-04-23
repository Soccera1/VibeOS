#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FS_MAX_PATH 128
#define FS_MAX_NAME 64

#define FS_S_IFMT 0170000u
#define FS_S_IFIFO 0010000u
#define FS_S_IFCHR 0020000u
#define FS_S_IFDIR 0040000u
#define FS_S_IFREG 0100000u
#define FS_S_IFLNK 0120000u
#define FS_S_IFSOCK 0140000u

#define FS_DT_UNKNOWN 0
#define FS_DT_FIFO 1
#define FS_DT_CHR 2
#define FS_DT_DIR 4
#define FS_DT_REG 8
#define FS_DT_LNK 10
#define FS_DT_SOCK 12

enum fs_backend {
    FS_BACKEND_NONE = 0,
    FS_BACKEND_INITRAMFS,
    FS_BACKEND_EXT2,
};

struct fs_entry {
    char path[FS_MAX_PATH];
    const uint8_t* data;
    size_t size;
    uint32_t mode;
    uint32_t inode;
    enum fs_backend backend;
};

void fs_init(const uint8_t* usrfs_start, size_t usrfs_size);
bool fs_usr_mount_ready(void);

int fs_lookup(const char* path, struct fs_entry* out);
int fs_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count);
int fs_readlink(const struct fs_entry* entry, char* out, size_t bufsz);

bool fs_path_has_child(const char* dir);
size_t fs_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children);

uint8_t fs_mode_to_dtype(uint32_t mode);
