#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fs.h"

void ext2_mount_image(const uint8_t* image, size_t size);
bool ext2_is_mounted(void);
bool ext2_owns_path(const char* path);

int ext2_lookup(const char* path, struct fs_entry* out);
int ext2_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count);
int ext2_readlink(const struct fs_entry* entry, char* out, size_t bufsz);

bool ext2_path_has_child(const char* dir);
size_t ext2_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children);
