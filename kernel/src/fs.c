#include "fs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ext2.h"
#include "initramfs.h"
#include "string.h"

static bool path_immediate_child(const char* dir, const char* full, char* child_out, size_t child_out_len) {
    if (strcmp(full, "/") == 0) {
        return false;
    }

    const char* rest = NULL;
    size_t dir_len = strlen(dir);
    if (strcmp(dir, "/") == 0) {
        if (full[0] != '/' || full[1] == '\0') {
            return false;
        }
        rest = full + 1;
    } else {
        if (strncmp(full, dir, dir_len) != 0 || full[dir_len] != '/') {
            return false;
        }
        rest = full + dir_len + 1;
    }

    if (*rest == '\0') {
        return false;
    }

    size_t i = 0;
    while (rest[i] != '\0' && rest[i] != '/' && i + 1 < child_out_len) {
        child_out[i] = rest[i];
        ++i;
    }
    child_out[i] = '\0';
    return i > 0;
}

static int child_index_of(char names[][FS_MAX_NAME], size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static bool path_in_usr_mount(const char* path) {
    return ext2_is_mounted() && ext2_owns_path(path);
}

void fs_init(const uint8_t* usrfs_start, size_t usrfs_size) {
    ext2_mount_image(usrfs_start, usrfs_size);
}

bool fs_usr_mount_ready(void) {
    return ext2_is_mounted();
}

uint8_t fs_mode_to_dtype(uint32_t mode) {
    switch (mode & FS_S_IFMT) {
        case FS_S_IFREG:
            return FS_DT_REG;
        case FS_S_IFDIR:
            return FS_DT_DIR;
        case FS_S_IFCHR:
            return FS_DT_CHR;
        case FS_S_IFIFO:
            return FS_DT_FIFO;
        case FS_S_IFLNK:
            return FS_DT_LNK;
        case FS_S_IFSOCK:
            return FS_DT_SOCK;
        default:
            return FS_DT_UNKNOWN;
    }
}

int fs_lookup(const char* path, struct fs_entry* out) {
    if (path == NULL) {
        return -22;
    }

    if (path_in_usr_mount(path)) {
        return ext2_lookup(path, out);
    }

    struct initramfs_entry entry;
    if (initramfs_find(path, &entry) != 0) {
        return -2;
    }

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        strncpy(out->path, entry.path, sizeof(out->path));
        out->path[sizeof(out->path) - 1] = '\0';
        out->data = entry.data;
        out->size = entry.size;
        out->mode = entry.mode;
        out->inode = 0;
        out->backend = FS_BACKEND_INITRAMFS;
    }

    return 0;
}

int fs_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count) {
    if (entry == NULL || buf == NULL) {
        return -22;
    }
    if (offset >= entry->size) {
        return 0;
    }

    size_t remain = entry->size - offset;
    size_t n = (count < remain) ? count : remain;

    if (entry->backend == FS_BACKEND_INITRAMFS) {
        memcpy(buf, entry->data + offset, n);
        return (int)n;
    }
    if (entry->backend == FS_BACKEND_EXT2) {
        return ext2_read(entry, offset, buf, n);
    }

    return -22;
}

int fs_readlink(const struct fs_entry* entry, char* out, size_t bufsz) {
    if (entry == NULL || out == NULL) {
        return -22;
    }
    if ((entry->mode & FS_S_IFMT) != FS_S_IFLNK) {
        return -22;
    }

    if (entry->backend == FS_BACKEND_INITRAMFS) {
        size_t n = entry->size;
        if (n > bufsz) {
            n = bufsz;
        }
        memcpy(out, entry->data, n);
        return (int)n;
    }
    if (entry->backend == FS_BACKEND_EXT2) {
        return ext2_readlink(entry, out, bufsz);
    }

    return -22;
}

bool fs_path_has_child(const char* dir) {
    if (dir == NULL) {
        return false;
    }

    if (path_in_usr_mount(dir)) {
        return ext2_path_has_child(dir);
    }

    if (strcmp(dir, "/") == 0 && ext2_is_mounted()) {
        return true;
    }

    for (size_t i = 0; i < initramfs_entry_count(); ++i) {
        const struct initramfs_entry* entry = initramfs_entry_at(i);
        if (entry == NULL) {
            continue;
        }
        if (path_in_usr_mount(entry->path)) {
            continue;
        }
        if (strcmp(dir, "/") == 0) {
            if (strcmp(entry->path, "/") != 0) {
                return true;
            }
            continue;
        }

        size_t dir_len = strlen(dir);
        if (strncmp(entry->path, dir, dir_len) == 0 && entry->path[dir_len] == '/' && entry->path[dir_len + 1] != '\0') {
            return true;
        }
    }

    return false;
}

size_t fs_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children) {
    size_t count = 0;

    if (dir == NULL || max_children == 0) {
        return 0;
    }

    if (!path_in_usr_mount(dir)) {
        for (size_t i = 0; i < initramfs_entry_count(); ++i) {
            const struct initramfs_entry* entry = initramfs_entry_at(i);
            if (entry == NULL) {
                continue;
            }
            if (path_in_usr_mount(entry->path)) {
                continue;
            }

            char child[FS_MAX_NAME];
            if (!path_immediate_child(dir, entry->path, child, sizeof(child))) {
                continue;
            }
            if (child_index_of(names, count, child) >= 0) {
                continue;
            }
            if (count >= max_children) {
                return count;
            }

            strncpy(names[count], child, FS_MAX_NAME);
            names[count][FS_MAX_NAME - 1] = '\0';

            struct fs_entry resolved;
            if (fs_lookup(entry->path, &resolved) == 0) {
                types[count] = fs_mode_to_dtype(resolved.mode);
            } else {
                types[count] = FS_DT_UNKNOWN;
            }
            ++count;
        }

        if (strcmp(dir, "/") == 0 && ext2_is_mounted() && child_index_of(names, count, "usr") < 0 && count < max_children) {
            strcpy(names[count], "usr");
            types[count] = FS_DT_DIR;
            ++count;
        }
    }

    if (ext2_is_mounted()) {
        count += ext2_collect_children(dir, &names[count], &types[count], max_children - count);
    }

    return count;
}
