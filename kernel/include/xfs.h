#pragma once

#include "ext2.h"

/* Storage callbacks use byte offsets and return zero on success. Writable
 * mounts require CONFIG_KERNEL_XFS_WRITE and a durability barrier callback. */
int xfs_mount_storage_at(const char* path, const struct ext2_storage_ops* ops,
                         void* ctx, size_t size, bool read_only);
int xfs_mount_image_at(const char* path, const uint8_t* image, size_t size, bool read_only);
int xfs_mount_file_at(const char* path, const struct fs_entry* file, bool read_only);
bool xfs_is_mounted_at(const char* path);
bool xfs_owns_path(const char* path);
int xfs_lookup(const char* path, struct fs_entry* out);
int xfs_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count);
int xfs_readlink(const struct fs_entry* entry, char* buf, size_t count);
size_t xfs_collect_children(const char* path, char names[][FS_MAX_NAME], uint8_t types[], size_t max);

int xfs_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count);
int xfs_truncate(struct fs_entry* entry, size_t size);
int xfs_create(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, struct fs_entry* out);
int xfs_mknod(const char* path, uint32_t mode, uint32_t rdev, uint32_t uid, uint32_t gid, struct fs_entry* out);
int xfs_mkdir(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, struct fs_entry* out);
int xfs_symlink(const char* target, const char* linkpath, uint32_t uid, uint32_t gid, struct fs_entry* out);
int xfs_link(const char* existing, const char* newpath);
int xfs_unlink(const char* path);
int xfs_rmdir(const char* path);
int xfs_rename(const char* oldpath, const char* newpath);
int xfs_chmod(const char* path, uint32_t mode);
int xfs_chown(const char* path, uint32_t uid, uint32_t gid);
int xfs_utime(const char* path, uint32_t atime, uint32_t mtime);
int xfs_sync_all(void);
bool xfs_is_read_only_path(const char* path);
bool xfs_same_file(const struct fs_entry*, const struct fs_entry*);
void xfs_set_inode_busy_checker(bool (*checker)(const char*, uint64_t));

struct xfs_metadata {
    uint64_t device, size, blocks;
    uint32_t mode, uid, gid, nlink, rdev;
    int64_t seconds[3];
    uint32_t nanoseconds[3];
};
int xfs_get_metadata(const struct fs_entry* entry, struct xfs_metadata* out);
int xfs_readdir(const struct fs_entry* entry, uint64_t start, char names[][FS_MAX_NAME],
                uint8_t types[], uint64_t numbers[], size_t max);

/* Descriptor metadata operations: 0 chmod, 1 chown, 2 utime. */
int xfs_change_metadata_entry(const struct fs_entry* entry, unsigned operation, uint32_t a, uint32_t b);
