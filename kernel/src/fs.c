#include "fs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ata.h"
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

static bool path_in_ext2_mount(const char* path) {
    return ext2_is_mounted() && ext2_owns_path(path);
}

enum boot_ext2_source {
    BOOT_EXT2_SOURCE_IMAGE,
    BOOT_EXT2_SOURCE_FILE,
    BOOT_EXT2_SOURCE_ATA_SECONDARY,
};

struct boot_ext2_mount {
    const char* mount_path;
    bool read_only;
    enum boot_ext2_source source;
    const uint8_t* image;
    size_t size;
    const char* file_path;
};

bool fs_mount_ready(const char* mount_path) {
    return ext2_is_mounted_at(mount_path);
}

int fs_mount_ext2_image(const char* mount_path, const uint8_t* image, size_t size, bool read_only) {
    return ext2_mount_image_at(mount_path, image, size, read_only);
}

int fs_mount_ext2_file(const char* mount_path, const char* path, bool read_only) {
    struct fs_entry entry;
    int lr = fs_lookup(path, &entry);
    if (lr != 0) {
        return lr;
    }
    return ext2_mount_file_at(mount_path, &entry, read_only);
}

int fs_mount_ext2_storage(const char* mount_path, const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only) {
    return ext2_mount_storage_at(mount_path, ops, ctx, size, read_only);
}

void fs_init(const uint8_t* usrfs_start, size_t usrfs_size) {
    struct boot_ext2_mount mounts[] = {
        {
            .mount_path = "/usr",
            .read_only = true,
            .source = (usrfs_start != NULL && usrfs_size != 0u) ? BOOT_EXT2_SOURCE_IMAGE : BOOT_EXT2_SOURCE_FILE,
            .image = usrfs_start,
            .size = usrfs_size,
            .file_path = "/boot/usr.ext3",
        },
        {
            .mount_path = "/home",
            .read_only = false,
            .source = BOOT_EXT2_SOURCE_ATA_SECONDARY,
            .image = NULL,
            .size = 0u,
            .file_path = NULL,
        },
    };

    for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); ++i) {
        int r = -1;
        switch (mounts[i].source) {
            case BOOT_EXT2_SOURCE_IMAGE:
                r = fs_mount_ext2_image(mounts[i].mount_path, mounts[i].image, mounts[i].size, mounts[i].read_only);
                break;
            case BOOT_EXT2_SOURCE_FILE:
                r = fs_mount_ext2_file(mounts[i].mount_path, mounts[i].file_path, mounts[i].read_only);
                break;
            case BOOT_EXT2_SOURCE_ATA_SECONDARY:
                if (ata_secondary_present()) {
                    r = fs_mount_ext2_storage(mounts[i].mount_path, ata_secondary_storage_ops(), ata_secondary_storage_ctx(),
                                              ata_secondary_size(), mounts[i].read_only);
                }
                break;
        }
        if (r != 0) {
            (void)fs_mount_ext2_image(mounts[i].mount_path, NULL, 0, mounts[i].read_only);
        }
    }
}

bool fs_usr_mount_ready(void) {
    return fs_mount_ready("/usr");
}

bool fs_home_mount_ready(void) {
    return fs_mount_ready("/home");
}

int fs_sync(void) {
    return ext2_sync_all();
}

int fs_shutdown(void) {
    return ext2_shutdown_all();
}

int fs_mount_usr_from_file(const char* path, bool read_only) {
    return fs_mount_ext2_file("/usr", path, read_only);
}

uint8_t fs_mode_to_dtype(uint32_t mode) {
    switch (mode & FS_S_IFMT) {
        case FS_S_IFREG:
            return FS_DT_REG;
        case FS_S_IFDIR:
            return FS_DT_DIR;
        case FS_S_IFCHR:
            return FS_DT_CHR;
        case FS_S_IFBLK:
            return FS_DT_BLK;
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

    if (path_in_ext2_mount(path)) {
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
        out->read_only = true;
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

int fs_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count) {
    if (entry == NULL || (buf == NULL && count != 0)) {
        return -22;
    }
    if (entry->read_only) {
        return -30;
    }

    if (entry->backend == FS_BACKEND_EXT2) {
        return ext2_write(entry, offset, buf, count);
    }

    return -30;
}

int fs_truncate(struct fs_entry* entry, size_t size) {
    if (entry == NULL) {
        return -22;
    }
    if (entry->read_only) {
        return -30;
    }

    if (entry->backend == FS_BACKEND_EXT2) {
        return ext2_truncate(entry, size);
    }

    return -30;
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

bool fs_is_read_only_path(const char* path) {
    if (path == NULL) {
        return true;
    }

    if (path_in_ext2_mount(path)) {
        return ext2_is_read_only_path(path);
    }

    struct fs_entry entry;
    if (fs_lookup(path, &entry) == 0) {
        return entry.read_only;
    }

    return false;
}

int fs_create(const char* path, uint32_t mode, struct fs_entry* out) {
    if (path_in_ext2_mount(path)) {
        return ext2_create(path, mode, out);
    }
    return -30;
}

int fs_mknod(const char* path, uint32_t mode, uint32_t rdev, struct fs_entry* out) {
    if (path_in_ext2_mount(path)) {
        return ext2_mknod(path, mode, rdev, out);
    }
    return -30;
}

int fs_mkdir(const char* path, uint32_t mode, struct fs_entry* out) {
    if (path_in_ext2_mount(path)) {
        return ext2_mkdir(path, mode, out);
    }
    return -30;
}

int fs_symlink(const char* target, const char* linkpath, struct fs_entry* out) {
    if (path_in_ext2_mount(linkpath)) {
        return ext2_symlink(target, linkpath, out);
    }
    return -30;
}

int fs_link(const char* existing, const char* newpath) {
    if (path_in_ext2_mount(existing) && path_in_ext2_mount(newpath)) {
        return ext2_link(existing, newpath);
    }
    return -30;
}

int fs_unlink(const char* path) {
    if (path_in_ext2_mount(path)) {
        return ext2_unlink(path);
    }
    return -30;
}

int fs_rmdir(const char* path) {
    if (path_in_ext2_mount(path)) {
        return ext2_rmdir(path);
    }
    return -30;
}

int fs_rename(const char* oldpath, const char* newpath) {
    if (path_in_ext2_mount(oldpath) && path_in_ext2_mount(newpath)) {
        return ext2_rename(oldpath, newpath);
    }
    return -30;
}

int fs_chmod(const char* path, uint32_t mode) {
    if (path_in_ext2_mount(path)) {
        return ext2_chmod(path, mode);
    }
    return -30;
}

int fs_chown(const char* path, uint32_t uid, uint32_t gid) {
    if (path_in_ext2_mount(path)) {
        return ext2_chown(path, uid, gid);
    }
    return -30;
}

bool fs_path_has_child(const char* dir) {
    if (dir == NULL) {
        return false;
    }

    if (path_in_ext2_mount(dir)) {
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
        if (path_in_ext2_mount(entry->path)) {
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

    if (!path_in_ext2_mount(dir)) {
        for (size_t i = 0; i < initramfs_entry_count(); ++i) {
            const struct initramfs_entry* entry = initramfs_entry_at(i);
            if (entry == NULL) {
                continue;
            }
            if (path_in_ext2_mount(entry->path)) {
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

    }

    if (ext2_is_mounted()) {
        count += ext2_collect_children(dir, &names[count], &types[count], max_children - count);
    }

    return count;
}
