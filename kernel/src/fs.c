#include "fs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ata.h"
#include "ext2.h"
#include "initramfs.h"
#include "kmalloc.h"
#include "string.h"
#include "virtio_scsi.h"

#define EINVAL 22
#define ENOENT 2
#define EEXIST 17
#define ENOTDIR 20
#define EISDIR 21
#define ENOMEM 12
#define EROFS 30
#define ENOTEMPTY 39
#define EXDEV 18

#define RAMDISK_MAX_NODES 256u
#define RAMDISK_ROOT_INODE 1u

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

struct ramdisk_node {
    bool used;
    uint32_t inode;
    uint32_t parent;
    uint32_t mode;
    uint8_t* data;
    size_t size;
    char path[FS_MAX_PATH];
};

static bool g_home_ramdisk_mounted;
static struct ramdisk_node g_ramdisk_nodes[RAMDISK_MAX_NODES];
static uint32_t g_ramdisk_next_inode = RAMDISK_ROOT_INODE;

static bool path_in_home_ramdisk(const char* path) {
    if (!g_home_ramdisk_mounted || path == NULL) {
        return false;
    }
    return strcmp(path, "/home") == 0 || strncmp(path, "/home/", 6) == 0;
}

static struct ramdisk_node* ramdisk_find_inode(uint32_t inode) {
    for (size_t i = 0; i < RAMDISK_MAX_NODES; ++i) {
        if (g_ramdisk_nodes[i].used && g_ramdisk_nodes[i].inode == inode) {
            return &g_ramdisk_nodes[i];
        }
    }
    return NULL;
}

static struct ramdisk_node* ramdisk_find_path(const char* path) {
    if (path == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < RAMDISK_MAX_NODES; ++i) {
        if (g_ramdisk_nodes[i].used && strcmp(g_ramdisk_nodes[i].path, path) == 0) {
            return &g_ramdisk_nodes[i];
        }
    }
    return NULL;
}

static int ramdisk_split_parent(const char* path, char* parent, size_t parent_len, char* name, size_t name_len) {
    if (!path_in_home_ramdisk(path) || strcmp(path, "/home") == 0 || parent == NULL || name == NULL ||
        parent_len == 0 || name_len == 0) {
        return -EINVAL;
    }

    size_t len = strlen(path);
    size_t slash = len;
    while (slash > 0 && path[slash - 1] != '/') {
        --slash;
    }
    if (slash == 0 || slash == len || len - slash >= name_len) {
        return -EINVAL;
    }
    size_t plen = (slash == 1) ? 1 : slash - 1;
    if (plen >= parent_len) {
        return -EINVAL;
    }
    memcpy(parent, path, plen);
    parent[plen] = '\0';
    strncpy(name, path + slash, name_len);
    name[name_len - 1] = '\0';
    return 0;
}

static struct ramdisk_node* ramdisk_alloc_node(void) {
    for (size_t i = 0; i < RAMDISK_MAX_NODES; ++i) {
        if (!g_ramdisk_nodes[i].used) {
            memset(&g_ramdisk_nodes[i], 0, sizeof(g_ramdisk_nodes[i]));
            g_ramdisk_nodes[i].used = true;
            g_ramdisk_nodes[i].inode = ++g_ramdisk_next_inode;
            return &g_ramdisk_nodes[i];
        }
    }
    return NULL;
}

static int ramdisk_fill_entry(const struct ramdisk_node* node, struct fs_entry* out) {
    if (node == NULL) {
        return -ENOENT;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        strncpy(out->path, node->path, sizeof(out->path));
        out->path[sizeof(out->path) - 1] = '\0';
        out->data = node->data;
        out->size = node->size;
        out->mode = node->mode;
        out->inode = node->inode;
        out->backend = FS_BACKEND_RAMDISK;
        out->read_only = false;
    }
    return 0;
}

static int ramdisk_create_node(const char* path, uint32_t mode, const void* data, size_t size, struct fs_entry* out) {
    char parent_path[FS_MAX_PATH];
    char name[FS_MAX_NAME];
    int sr = ramdisk_split_parent(path, parent_path, sizeof(parent_path), name, sizeof(name));
    if (sr != 0) {
        return sr;
    }
    if (ramdisk_find_path(path) != NULL) {
        return -EEXIST;
    }
    struct ramdisk_node* parent = ramdisk_find_path(parent_path);
    if (parent == NULL) {
        return -ENOENT;
    }
    if ((parent->mode & FS_S_IFMT) != FS_S_IFDIR) {
        return -ENOTDIR;
    }

    struct ramdisk_node* node = ramdisk_alloc_node();
    if (node == NULL) {
        return -ENOMEM;
    }
    node->parent = parent->inode;
    node->mode = mode;
    strncpy(node->path, path, sizeof(node->path));
    node->path[sizeof(node->path) - 1] = '\0';
    if (size != 0u) {
        node->data = kmalloc(size);
        if (node->data == NULL) {
            node->used = false;
            return -ENOMEM;
        }
        memcpy(node->data, data, size);
        node->size = size;
    }
    return ramdisk_fill_entry(node, out);
}

static int ramdisk_mount_home(void) {
    memset(g_ramdisk_nodes, 0, sizeof(g_ramdisk_nodes));
    g_home_ramdisk_mounted = true;
    g_ramdisk_next_inode = RAMDISK_ROOT_INODE;
    g_ramdisk_nodes[0].used = true;
    g_ramdisk_nodes[0].inode = RAMDISK_ROOT_INODE;
    g_ramdisk_nodes[0].parent = RAMDISK_ROOT_INODE;
    g_ramdisk_nodes[0].mode = FS_S_IFDIR | 0755u;
    strcpy(g_ramdisk_nodes[0].path, "/home");
    return 0;
}

static int ramdisk_lookup(const char* path, struct fs_entry* out) {
    return ramdisk_fill_entry(ramdisk_find_path(path), out);
}

static int ramdisk_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count) {
    struct ramdisk_node* node = ramdisk_find_inode(entry->inode);
    if (node == NULL || buf == NULL) {
        return -EINVAL;
    }
    if (offset >= node->size) {
        return 0;
    }
    size_t n = count < node->size - offset ? count : node->size - offset;
    memcpy(buf, node->data + offset, n);
    return (int)n;
}

static int ramdisk_truncate_entry(struct fs_entry* entry, size_t size) {
    struct ramdisk_node* node = ramdisk_find_inode(entry->inode);
    if (node == NULL || (node->mode & FS_S_IFMT) == FS_S_IFDIR) {
        return node == NULL ? -EINVAL : -EISDIR;
    }
    if (size == node->size) {
        return 0;
    }
    uint8_t* new_data = NULL;
    if (size != 0u) {
        new_data = kmalloc(size);
        if (new_data == NULL) {
            return -ENOMEM;
        }
        size_t copy = node->size < size ? node->size : size;
        if (copy != 0u) {
            memcpy(new_data, node->data, copy);
        }
        if (size > copy) {
            memset(new_data + copy, 0, size - copy);
        }
    }
    if (node->data != NULL) {
        kfree(node->data);
    }
    node->data = new_data;
    node->size = size;
    entry->data = node->data;
    entry->size = node->size;
    return 0;
}

static int ramdisk_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count) {
    if (buf == NULL && count != 0u) {
        return -EINVAL;
    }
    if (offset + count < offset) {
        return -EINVAL;
    }
    size_t end = offset + count;
    if (end > entry->size) {
        int tr = ramdisk_truncate_entry(entry, end);
        if (tr != 0) {
            return tr;
        }
    }
    struct ramdisk_node* node = ramdisk_find_inode(entry->inode);
    if (node == NULL) {
        return -EINVAL;
    }
    if (count != 0u) {
        memcpy(node->data + offset, buf, count);
    }
    entry->data = node->data;
    entry->size = node->size;
    return (int)count;
}

static bool ramdisk_has_children(uint32_t inode) {
    for (size_t i = 0; i < RAMDISK_MAX_NODES; ++i) {
        if (g_ramdisk_nodes[i].used && g_ramdisk_nodes[i].parent == inode && g_ramdisk_nodes[i].inode != inode) {
            return true;
        }
    }
    return false;
}

static int ramdisk_replace_path_prefix(char* path, const char* old_prefix, const char* new_prefix) {
    size_t old_len = strlen(old_prefix);
    size_t new_len = strlen(new_prefix);
    size_t path_len = strlen(path);
    if (strncmp(path, old_prefix, old_len) != 0 || (path[old_len] != '\0' && path[old_len] != '/')) {
        return 0;
    }
    if (new_len + (path_len - old_len) >= FS_MAX_PATH) {
        return -EINVAL;
    }

    char updated[FS_MAX_PATH];
    memcpy(updated, new_prefix, new_len);
    strcpy(updated + new_len, path + old_len);
    strcpy(path, updated);
    return 0;
}

static int ramdisk_rename(const char* oldpath, const char* newpath) {
    if (!path_in_home_ramdisk(oldpath) || !path_in_home_ramdisk(newpath)) {
        return -EXDEV;
    }
    if (strcmp(oldpath, "/home") == 0) {
        return -EINVAL;
    }
    if (strcmp(oldpath, newpath) == 0) {
        return 0;
    }

    struct ramdisk_node* node = ramdisk_find_path(oldpath);
    if (node == NULL) {
        return -ENOENT;
    }
    if ((node->mode & FS_S_IFMT) == FS_S_IFDIR) {
        size_t old_len = strlen(oldpath);
        if (strncmp(newpath, oldpath, old_len) == 0 && newpath[old_len] == '/') {
            return -EINVAL;
        }
    }
    struct ramdisk_node* existing = ramdisk_find_path(newpath);
    if (existing != NULL) {
        if ((existing->mode & FS_S_IFMT) == FS_S_IFDIR) {
            if ((node->mode & FS_S_IFMT) != FS_S_IFDIR) {
                return -EISDIR;
            }
            if (ramdisk_has_children(existing->inode)) {
                return -ENOTEMPTY;
            }
        } else if ((node->mode & FS_S_IFMT) == FS_S_IFDIR) {
            return -ENOTDIR;
        }
    }

    char new_parent_path[FS_MAX_PATH];
    char new_name[FS_MAX_NAME];
    int sr = ramdisk_split_parent(newpath, new_parent_path, sizeof(new_parent_path), new_name, sizeof(new_name));
    if (sr != 0) {
        return sr;
    }
    struct ramdisk_node* new_parent = ramdisk_find_path(new_parent_path);
    if (new_parent == NULL) {
        return -ENOENT;
    }
    if ((new_parent->mode & FS_S_IFMT) != FS_S_IFDIR) {
        return -ENOTDIR;
    }

    char old_prefix[FS_MAX_PATH];
    char new_prefix[FS_MAX_PATH];
    strncpy(old_prefix, oldpath, sizeof(old_prefix));
    old_prefix[sizeof(old_prefix) - 1] = '\0';
    strncpy(new_prefix, newpath, sizeof(new_prefix));
    new_prefix[sizeof(new_prefix) - 1] = '\0';

    for (size_t i = 0; i < RAMDISK_MAX_NODES; ++i) {
        if (!g_ramdisk_nodes[i].used) {
            continue;
        }
        size_t old_len = strlen(old_prefix);
        size_t new_len = strlen(new_prefix);
        size_t path_len = strlen(g_ramdisk_nodes[i].path);
        if (strncmp(g_ramdisk_nodes[i].path, old_prefix, old_len) == 0 &&
            (g_ramdisk_nodes[i].path[old_len] == '\0' || g_ramdisk_nodes[i].path[old_len] == '/') &&
            new_len + (path_len - old_len) >= FS_MAX_PATH) {
            return -EINVAL;
        }
    }

    if (existing != NULL) {
        if (existing->data != NULL) {
            kfree(existing->data);
        }
        memset(existing, 0, sizeof(*existing));
    }

    node->parent = new_parent->inode;
    for (size_t i = 0; i < RAMDISK_MAX_NODES; ++i) {
        if (!g_ramdisk_nodes[i].used) {
            continue;
        }
        int rr = ramdisk_replace_path_prefix(g_ramdisk_nodes[i].path, old_prefix, new_prefix);
        if (rr != 0) {
            return rr;
        }
    }
    return 0;
}

enum boot_ext2_source {
    BOOT_EXT2_SOURCE_IMAGE,
    BOOT_EXT2_SOURCE_FILE,
    BOOT_EXT2_SOURCE_ATA_SECONDARY,
    BOOT_EXT2_SOURCE_SCSI,
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
            .source = BOOT_EXT2_SOURCE_SCSI,
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
            case BOOT_EXT2_SOURCE_SCSI:
                if (virtio_scsi_present()) {
                    r = fs_mount_ext2_storage(mounts[i].mount_path, virtio_scsi_storage_ops(), virtio_scsi_storage_ctx(),
                                              virtio_scsi_size(), mounts[i].read_only);
                } else if (ata_scsi_present()) {
                    r = fs_mount_ext2_storage(mounts[i].mount_path, ata_scsi_storage_ops(), ata_scsi_storage_ctx(),
                                              ata_scsi_size(), mounts[i].read_only);
                }
                break;
        }
        if (r != 0) {
            if (strcmp(mounts[i].mount_path, "/home") == 0) {
                (void)ramdisk_mount_home();
            } else {
                (void)fs_mount_ext2_image(mounts[i].mount_path, NULL, 0, mounts[i].read_only);
            }
        }
    }
}

bool fs_usr_mount_ready(void) {
    return fs_mount_ready("/usr");
}

bool fs_home_mount_ready(void) {
    return fs_mount_ready("/home");
}

bool fs_home_ramdisk_ready(void) {
    return g_home_ramdisk_mounted;
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
    if (path_in_home_ramdisk(path)) {
        return ramdisk_lookup(path, out);
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
    if (entry->backend == FS_BACKEND_RAMDISK) {
        return ramdisk_read(entry, offset, buf, count);
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
    if (entry->backend == FS_BACKEND_RAMDISK) {
        return ramdisk_write(entry, offset, buf, count);
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
    if (entry->backend == FS_BACKEND_RAMDISK) {
        return ramdisk_truncate_entry(entry, size);
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
    if (entry->backend == FS_BACKEND_RAMDISK) {
        return ramdisk_read(entry, 0, out, bufsz);
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
    if (path_in_home_ramdisk(path)) {
        uint32_t file_mode = (mode & FS_S_IFMT) == 0u ? (FS_S_IFREG | (mode & 07777u)) : mode;
        return ramdisk_create_node(path, file_mode, NULL, 0, out);
    }
    return -30;
}

int fs_mknod(const char* path, uint32_t mode, uint32_t rdev, struct fs_entry* out) {
    if (path_in_ext2_mount(path)) {
        return ext2_mknod(path, mode, rdev, out);
    }
    if (path_in_home_ramdisk(path)) {
        (void)rdev;
        return ramdisk_create_node(path, mode, NULL, 0, out);
    }
    return -30;
}

int fs_mkdir(const char* path, uint32_t mode, struct fs_entry* out) {
    if (path_in_ext2_mount(path)) {
        return ext2_mkdir(path, mode, out);
    }
    if (path_in_home_ramdisk(path)) {
        return ramdisk_create_node(path, FS_S_IFDIR | (mode & 07777u), NULL, 0, out);
    }
    return -30;
}

int fs_symlink(const char* target, const char* linkpath, struct fs_entry* out) {
    if (path_in_ext2_mount(linkpath)) {
        return ext2_symlink(target, linkpath, out);
    }
    if (path_in_home_ramdisk(linkpath)) {
        if (target == NULL) {
            return -EINVAL;
        }
        return ramdisk_create_node(linkpath, FS_S_IFLNK | 0777u, target, strlen(target), out);
    }
    return -30;
}

int fs_link(const char* existing, const char* newpath) {
    if (path_in_ext2_mount(existing) && path_in_ext2_mount(newpath)) {
        return ext2_link(existing, newpath);
    }
    if (path_in_home_ramdisk(existing) || path_in_home_ramdisk(newpath)) {
        return -EXDEV;
    }
    return -30;
}

int fs_unlink(const char* path) {
    if (path_in_ext2_mount(path)) {
        return ext2_unlink(path);
    }
    if (path_in_home_ramdisk(path)) {
        struct ramdisk_node* node = ramdisk_find_path(path);
        if (node == NULL) {
            return -ENOENT;
        }
        if ((node->mode & FS_S_IFMT) == FS_S_IFDIR) {
            return -EISDIR;
        }
        if (node->data != NULL) {
            kfree(node->data);
        }
        memset(node, 0, sizeof(*node));
        return 0;
    }
    return -30;
}

int fs_rmdir(const char* path) {
    if (path_in_ext2_mount(path)) {
        return ext2_rmdir(path);
    }
    if (path_in_home_ramdisk(path)) {
        struct ramdisk_node* node = ramdisk_find_path(path);
        if (node == NULL) {
            return -ENOENT;
        }
        if ((node->mode & FS_S_IFMT) != FS_S_IFDIR) {
            return -ENOTDIR;
        }
        if (node->inode == RAMDISK_ROOT_INODE) {
            return -EINVAL;
        }
        if (ramdisk_has_children(node->inode)) {
            return -ENOTEMPTY;
        }
        memset(node, 0, sizeof(*node));
        return 0;
    }
    return -30;
}

int fs_rename(const char* oldpath, const char* newpath) {
    if (path_in_ext2_mount(oldpath) && path_in_ext2_mount(newpath)) {
        return ext2_rename(oldpath, newpath);
    }
    if (path_in_home_ramdisk(oldpath) || path_in_home_ramdisk(newpath)) {
        return ramdisk_rename(oldpath, newpath);
    }
    return -30;
}

int fs_chmod(const char* path, uint32_t mode) {
    if (path_in_ext2_mount(path)) {
        return ext2_chmod(path, mode);
    }
    if (path_in_home_ramdisk(path)) {
        struct ramdisk_node* node = ramdisk_find_path(path);
        if (node == NULL) {
            return -ENOENT;
        }
        node->mode = (node->mode & FS_S_IFMT) | (mode & 07777u);
        return 0;
    }
    return -30;
}

int fs_chown(const char* path, uint32_t uid, uint32_t gid) {
    if (path_in_ext2_mount(path)) {
        return ext2_chown(path, uid, gid);
    }
    if (path_in_home_ramdisk(path)) {
        (void)uid;
        (void)gid;
        return ramdisk_find_path(path) == NULL ? -ENOENT : 0;
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
    if (path_in_home_ramdisk(dir)) {
        struct ramdisk_node* node = ramdisk_find_path(dir);
        return node != NULL && ramdisk_has_children(node->inode);
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

    if (path_in_home_ramdisk(dir)) {
        struct ramdisk_node* parent = ramdisk_find_path(dir);
        if (parent != NULL) {
            for (size_t i = 0; i < RAMDISK_MAX_NODES && count < max_children; ++i) {
                if (!g_ramdisk_nodes[i].used || g_ramdisk_nodes[i].parent != parent->inode ||
                    g_ramdisk_nodes[i].inode == parent->inode) {
                    continue;
                }
                char child[FS_MAX_NAME];
                if (!path_immediate_child(dir, g_ramdisk_nodes[i].path, child, sizeof(child))) {
                    continue;
                }
                if (child_index_of(names, count, child) >= 0) {
                    continue;
                }
                strncpy(names[count], child, FS_MAX_NAME);
                names[count][FS_MAX_NAME - 1] = '\0';
                types[count] = fs_mode_to_dtype(g_ramdisk_nodes[i].mode);
                ++count;
            }
        }
    }

    if (ext2_is_mounted()) {
        count += ext2_collect_children(dir, &names[count], &types[count], max_children - count);
    }

    return count;
}
