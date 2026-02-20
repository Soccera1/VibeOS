#include "initramfs.h"

#include <stdbool.h>
#include <stdint.h>

#include "string.h"

#define MAX_INITRAMFS_ENTRIES 1024

struct cpio_newc {
    char c_magic[6];
    char c_ino[8];
    char c_mode[8];
    char c_uid[8];
    char c_gid[8];
    char c_nlink[8];
    char c_mtime[8];
    char c_filesize[8];
    char c_devmajor[8];
    char c_devminor[8];
    char c_rdevmajor[8];
    char c_rdevminor[8];
    char c_namesize[8];
    char c_check[8];
} __attribute__((packed));

static struct initramfs_entry g_entries[MAX_INITRAMFS_ENTRIES];
static size_t g_entry_count;

static uint32_t parse_hex(const char* s, size_t n) {
    uint32_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v <<= 4;
        char c = s[i];
        if (c >= '0' && c <= '9') {
            v |= (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= (uint32_t)(10 + c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            v |= (uint32_t)(10 + c - 'A');
        }
    }
    return v;
}

static void normalize_path(const char* in, char* out, size_t out_len) {
    size_t i = 0;
    size_t j = 0;

    while (in[i] == '.') {
        if (in[i + 1] == '/') {
            i += 2;
            continue;
        }
        if (in[i + 1] == '\0') {
            i += 1;
            break;
        }
        break;
    }

    while (in[i] == '/') {
        ++i;
    }

    out[j++] = '/';
    while (in[i] != '\0' && j + 1 < out_len) {
        if (in[i] == '/' && in[i + 1] == '/') {
            ++i;
            continue;
        }
        out[j++] = in[i++];
    }

    if (j > 1 && out[j - 1] == '/') {
        --j;
    }
    out[j] = '\0';
}

void initramfs_init(const uint8_t* start, size_t size) {
    g_entry_count = 0;

    if (start == 0 || size < sizeof(struct cpio_newc)) {
        return;
    }

    const uint8_t* ptr = start;
    const uint8_t* end = start + size;

    while (ptr + sizeof(struct cpio_newc) <= end) {
        const struct cpio_newc* hdr = (const struct cpio_newc*)ptr;
        if (memcmp(hdr->c_magic, "070701", 6) != 0) {
            break;
        }

        uint32_t name_size = parse_hex(hdr->c_namesize, 8);
        uint32_t file_size = parse_hex(hdr->c_filesize, 8);
        uint32_t mode = parse_hex(hdr->c_mode, 8);

        const char* name = (const char*)(ptr + sizeof(struct cpio_newc));
        const uint8_t* data = (const uint8_t*)name + name_size;

        uintptr_t aligned_name_end = ((uintptr_t)data + 3u) & ~3u;
        data = (const uint8_t*)aligned_name_end;

        if (name_size == 0) {
            break;
        }

        if (strcmp(name, "TRAILER!!!") == 0) {
            break;
        }

        if (g_entry_count < MAX_INITRAMFS_ENTRIES) {
            struct initramfs_entry* e = &g_entries[g_entry_count++];
            normalize_path(name, e->path, sizeof(e->path));
            e->data = data;
            e->size = file_size;
            e->mode = mode;
        }

        uintptr_t next = (uintptr_t)data + file_size;
        next = (next + 3u) & ~3u;
        ptr = (const uint8_t*)next;
    }
}

int initramfs_find(const char* path, struct initramfs_entry* out) {
    char normalized[128];
    normalize_path(path, normalized, sizeof(normalized));

    for (size_t i = 0; i < g_entry_count; ++i) {
        if (strcmp(g_entries[i].path, normalized) == 0) {
            if (out != 0) {
                *out = g_entries[i];
            }
            return 0;
        }
    }

    return -1;
}

size_t initramfs_entry_count(void) {
    return g_entry_count;
}

const struct initramfs_entry* initramfs_entry_at(size_t idx) {
    if (idx >= g_entry_count) {
        return 0;
    }
    return &g_entries[idx];
}
