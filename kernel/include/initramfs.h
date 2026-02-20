#pragma once

#include <stddef.h>
#include <stdint.h>

struct initramfs_entry {
    char path[128];
    const uint8_t* data;
    size_t size;
    uint32_t mode;
};

void initramfs_init(const uint8_t* start, size_t size);
int initramfs_find(const char* path, struct initramfs_entry* out);
size_t initramfs_entry_count(void);
const struct initramfs_entry* initramfs_entry_at(size_t idx);
