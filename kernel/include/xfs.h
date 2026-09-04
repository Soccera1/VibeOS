#pragma once

#include "ext2.h"

/* XFS is read-only. Storage callbacks use byte offsets and return zero on success. */
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
