#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fs.h"

struct ext2_storage_ops {
    int (*read)(void* ctx, uint64_t offset, void* buf, size_t len);
    int (*write)(void* ctx, uint64_t offset, const void* buf, size_t len);
};

int ext2_mount_storage_at(const char* mount_path, const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only);
int ext2_mount_storage(const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only);
int ext2_mount_image_at(const char* mount_path, const uint8_t* image, size_t size, bool read_only);
void ext2_mount_image(const uint8_t* image, size_t size, bool read_only);
int ext2_mount_file_at(const char* mount_path, const struct fs_entry* image_file, bool read_only);
int ext2_mount_file(const struct fs_entry* image_file, bool read_only);
bool ext2_is_mounted(void);
bool ext2_is_mounted_at(const char* mount_path);
bool ext2_is_read_only(void);
bool ext2_is_read_only_path(const char* path);
bool ext2_owns_path(const char* path);
int ext2_sync_all(void);
int ext2_shutdown_all(void);

int ext2_lookup(const char* path, struct fs_entry* out);
int ext2_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count);
int ext2_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count);
int ext2_truncate(struct fs_entry* entry, size_t size);
int ext2_readlink(const struct fs_entry* entry, char* out, size_t bufsz);
int ext2_create(const char* path, uint32_t mode, struct fs_entry* out);
int ext2_mknod(const char* path, uint32_t mode, uint32_t rdev, struct fs_entry* out);
int ext2_mkdir(const char* path, uint32_t mode, struct fs_entry* out);
int ext2_symlink(const char* target, const char* linkpath, struct fs_entry* out);
int ext2_link(const char* existing, const char* newpath);
int ext2_unlink(const char* path);
int ext2_rmdir(const char* path);
int ext2_rename(const char* oldpath, const char* newpath);
int ext2_chmod(const char* path, uint32_t mode);
int ext2_chown(const char* path, uint32_t uid, uint32_t gid);

bool ext2_path_has_child(const char* dir);
size_t ext2_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children);
