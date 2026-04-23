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
#define FS_S_IFBLK 0060000u
#define FS_S_IFREG 0100000u
#define FS_S_IFLNK 0120000u
#define FS_S_IFSOCK 0140000u

#define FS_DT_UNKNOWN 0
#define FS_DT_FIFO 1
#define FS_DT_CHR 2
#define FS_DT_DIR 4
#define FS_DT_BLK 6
#define FS_DT_REG 8
#define FS_DT_LNK 10
#define FS_DT_SOCK 12

enum fs_backend {
    FS_BACKEND_NONE = 0,
    FS_BACKEND_INITRAMFS,
    FS_BACKEND_EXT2,
};

struct ext2_storage_ops;

struct fs_entry {
    char path[FS_MAX_PATH];
    const uint8_t* data;
    size_t size;
    uint32_t mode;
    uint32_t inode;
    enum fs_backend backend;
    bool read_only;
};

void fs_init(const uint8_t* usrfs_start, size_t usrfs_size);
bool fs_mount_ready(const char* mount_path);
bool fs_usr_mount_ready(void);
bool fs_home_mount_ready(void);
int fs_sync(void);
int fs_shutdown(void);
int fs_mount_ext2_image(const char* mount_path, const uint8_t* image, size_t size, bool read_only);
int fs_mount_ext2_file(const char* mount_path, const char* path, bool read_only);
int fs_mount_ext2_storage(const char* mount_path, const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only);
int fs_mount_usr_from_file(const char* path, bool read_only);

int fs_lookup(const char* path, struct fs_entry* out);
int fs_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count);
int fs_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count);
int fs_truncate(struct fs_entry* entry, size_t size);
int fs_readlink(const struct fs_entry* entry, char* out, size_t bufsz);
bool fs_is_read_only_path(const char* path);
int fs_create(const char* path, uint32_t mode, struct fs_entry* out);
int fs_mknod(const char* path, uint32_t mode, uint32_t rdev, struct fs_entry* out);
int fs_mkdir(const char* path, uint32_t mode, struct fs_entry* out);
int fs_symlink(const char* target, const char* linkpath, struct fs_entry* out);
int fs_link(const char* existing, const char* newpath);
int fs_unlink(const char* path);
int fs_rmdir(const char* path);
int fs_rename(const char* oldpath, const char* newpath);
int fs_chmod(const char* path, uint32_t mode);
int fs_chown(const char* path, uint32_t uid, uint32_t gid);

bool fs_path_has_child(const char* dir);
size_t fs_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children);

uint8_t fs_mode_to_dtype(uint32_t mode);
