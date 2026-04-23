#include "ext2.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "kmalloc.h"
#include "string.h"

#define EINVAL 22
#define ENOENT 2
#define EEXIST 17
#define EXDEV 18
#define ENOTDIR 20
#define EISDIR 21
#define ENOMEM 12
#define ENOSPC 28
#define EROFS 30
#define ENOTEMPTY 39
#define ENOTSUP 95

#define EXT2_SUPER_MAGIC 0xEF53u
#define EXT2_ROOT_INO 2u
#define EXT2_NDIR_BLOCKS 12u
#define EXT2_IND_BLOCK 12u
#define EXT2_DIND_BLOCK 13u
#define EXT2_TIND_BLOCK 14u
#define EXT2_NAME_LEN 255u
#define EXT2_VALID_FS 0x0001u

#define EXT2_FT_UNKNOWN 0u
#define EXT2_FT_REG_FILE 1u
#define EXT2_FT_DIR 2u
#define EXT2_FT_CHRDEV 3u
#define EXT2_FT_BLKDEV 4u
#define EXT2_FT_FIFO 5u
#define EXT2_FT_SOCK 6u
#define EXT2_FT_SYMLINK 7u
#define EXT2_CACHE_SLOTS 8u
#define EXT2_MAX_MOUNTS 4u

struct ext2_superblock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t s_uuid[16];
    char s_volume_name[16];
    char s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
} __attribute__((packed));

struct ext2_group_desc {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t bg_reserved[12];
} __attribute__((packed));

struct ext2_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint8_t i_osd2[12];
} __attribute__((packed));

struct ext2_dirent_head {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
} __attribute__((packed));

struct ext2_mount;

struct ext2_file_storage_ctx {
    struct fs_entry backing;
    struct ext2_mount* host;
};

struct ext2_mount {
    bool mounted;
    bool read_only;
    char mount_path[FS_MAX_PATH];
    size_t mount_path_len;
    const struct ext2_storage_ops* ops;
    void* storage_ctx;
    size_t size;
    struct ext2_superblock superblock;
    uint32_t block_size;
    uint32_t inodes_count;
    uint32_t blocks_count;
    uint32_t first_data_block;
    uint32_t blocks_per_group;
    uint32_t inodes_per_group;
    uint32_t first_ino;
    uint32_t inode_size;
    uint32_t group_count;
    uint64_t cache_clock;
    struct {
        bool valid;
        bool dirty;
        uint32_t block_num;
        uint64_t last_use;
        uint8_t* data;
    } cache[EXT2_CACHE_SLOTS];
    struct ext2_file_storage_ctx file_storage;
};

static struct ext2_mount g_ext2_mounts[EXT2_MAX_MOUNTS];
static struct ext2_mount* g_ext2_current = &g_ext2_mounts[0];
#define g_ext2 (*g_ext2_current)

static int min_int(int a, int b) {
    return (a < b) ? a : b;
}

static uint16_t ext2_dir_rec_len(size_t name_len) {
    return (uint16_t)((sizeof(struct ext2_dirent_head) + name_len + 3u) & ~3u);
}

static int ext2_mem_read(void* ctx, uint64_t offset, void* buf, size_t len) {
    const uint8_t* base = (const uint8_t*)ctx;
    if (base == NULL || buf == NULL) {
        return -EINVAL;
    }
    memcpy(buf, base + offset, len);
    return 0;
}

static int ext2_mem_write(void* ctx, uint64_t offset, const void* buf, size_t len) {
    uint8_t* base = (uint8_t*)ctx;
    if (base == NULL || (buf == NULL && len != 0)) {
        return -EINVAL;
    }
    memcpy(base + offset, buf, len);
    return 0;
}

static const struct ext2_storage_ops g_ext2_mem_ops = {
    .read = ext2_mem_read,
    .write = ext2_mem_write,
};

static bool ext2_internal_path_for_mount(const struct ext2_mount* mount, const char* path, const char** internal_out) {
    if (mount == NULL || !mount->mounted || path == NULL) {
        return false;
    }

    if (mount->mount_path_len == 0 || mount->mount_path_len >= FS_MAX_PATH) {
        return false;
    }

    if (strcmp(path, mount->mount_path) == 0) {
        *internal_out = "/";
        return true;
    }

    if (mount->mount_path_len == 1u && mount->mount_path[0] == '/') {
        if (path[0] != '/') {
            return false;
        }
        *internal_out = path;
        return true;
    }

    if (strncmp(path, mount->mount_path, mount->mount_path_len) == 0 && path[mount->mount_path_len] == '/') {
        *internal_out = path + mount->mount_path_len;
        return true;
    }

    return false;
}

static struct ext2_mount* ext2_find_mount_by_exact_path(const char* mount_path) {
    if (mount_path == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
        if (g_ext2_mounts[i].mounted && strcmp(g_ext2_mounts[i].mount_path, mount_path) == 0) {
            return &g_ext2_mounts[i];
        }
    }

    return NULL;
}

static struct ext2_mount* ext2_find_mount_by_path(const char* path, const char** internal_out) {
    struct ext2_mount* best = NULL;
    size_t best_len = 0;
    const char* best_internal = NULL;

    for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
        const char* internal = NULL;
        if (!ext2_internal_path_for_mount(&g_ext2_mounts[i], path, &internal)) {
            continue;
        }
        if (g_ext2_mounts[i].mount_path_len >= best_len) {
            best = &g_ext2_mounts[i];
            best_len = g_ext2_mounts[i].mount_path_len;
            best_internal = internal;
        }
    }

    if (best != NULL && internal_out != NULL) {
        *internal_out = best_internal;
    }
    return best;
}

static struct ext2_mount* ext2_find_free_mount_slot(void) {
    for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
        if (!g_ext2_mounts[i].mounted) {
            return &g_ext2_mounts[i];
        }
    }
    return NULL;
}

static void release_mount_cache(struct ext2_mount* mount) {
    if (mount == NULL) {
        return;
    }

    for (size_t i = 0; i < EXT2_CACHE_SLOTS; ++i) {
        if (mount->cache[i].data != NULL) {
            kfree(mount->cache[i].data);
            mount->cache[i].data = NULL;
        }
    }
}

static int ext2_file_storage_rw(struct ext2_file_storage_ctx* ctx, uint64_t offset, void* buf, size_t len, bool write) {
    if (ctx == NULL || buf == NULL || offset + len < offset || offset + len > ctx->backing.size) {
        return -EINVAL;
    }

    struct ext2_mount* saved = g_ext2_current;
    if (ctx->host != NULL) {
        g_ext2_current = ctx->host;
    }

    int r = write ? fs_write(&ctx->backing, (size_t)offset, buf, len) : fs_read(&ctx->backing, (size_t)offset, buf, len);

    g_ext2_current = saved;

    if (r < 0) {
        return r;
    }
    return ((size_t)r == len) ? 0 : -EINVAL;
}

static int ext2_file_read(void* ctx, uint64_t offset, void* buf, size_t len) {
    return ext2_file_storage_rw((struct ext2_file_storage_ctx*)ctx, offset, buf, len, false);
}

static int ext2_file_write(void* ctx, uint64_t offset, const void* buf, size_t len) {
    return ext2_file_storage_rw((struct ext2_file_storage_ctx*)ctx, offset, (void*)buf, len, true);
}

static const struct ext2_storage_ops g_ext2_file_ops = {
    .read = ext2_file_read,
    .write = ext2_file_write,
};

static int flush_block_cache(void);

static int storage_read(uint64_t offset, void* buf, size_t len) {
    if (!g_ext2.mounted || g_ext2.ops == NULL || g_ext2.ops->read == NULL || buf == NULL) {
        return -EINVAL;
    }
    if (offset + len < offset || offset + len > g_ext2.size) {
        return -EINVAL;
    }
    return g_ext2.ops->read(g_ext2.storage_ctx, offset, buf, len);
}

static int storage_write(uint64_t offset, const void* buf, size_t len) {
    if (!g_ext2.mounted || g_ext2.read_only || g_ext2.ops == NULL || g_ext2.ops->write == NULL) {
        return g_ext2.read_only ? -EROFS : -EINVAL;
    }
    if (offset + len < offset || offset + len > g_ext2.size) {
        return -EINVAL;
    }
    return g_ext2.ops->write(g_ext2.storage_ctx, offset, buf, len);
}

static int write_superblock(void) {
    return storage_write(1024u, &g_ext2.superblock, sizeof(g_ext2.superblock));
}

static int ext2_sync_current(bool clean_unmount) {
    if (!g_ext2.mounted) {
        return 0;
    }

    int r = flush_block_cache();
    if (r != 0) {
        return r;
    }

    if (!g_ext2.read_only && clean_unmount) {
        g_ext2.superblock.s_state |= EXT2_VALID_FS;
        r = write_superblock();
        if (r != 0) {
            return r;
        }
    }

    return 0;
}

static int flush_cache_slot(size_t slot) {
    if (slot >= EXT2_CACHE_SLOTS || !g_ext2.cache[slot].valid || !g_ext2.cache[slot].dirty) {
        return 0;
    }

    uint64_t offset = (uint64_t)g_ext2.cache[slot].block_num * g_ext2.block_size;
    int r = storage_write(offset, g_ext2.cache[slot].data, g_ext2.block_size);
    if (r == 0) {
        g_ext2.cache[slot].dirty = false;
    }
    return r;
}

static int flush_block_cache(void) {
    for (size_t i = 0; i < EXT2_CACHE_SLOTS; ++i) {
        int r = flush_cache_slot(i);
        if (r != 0) {
            return r;
        }
    }
    return 0;
}

static uint8_t* cache_block_ptr(uint32_t block_num, bool writable) {
    if (block_num == 0) {
        return NULL;
    }
    uint64_t offset = (uint64_t)block_num * g_ext2.block_size;
    if (offset + g_ext2.block_size > g_ext2.size) {
        return NULL;
    }

    size_t victim = 0;
    uint64_t oldest = UINT64_MAX;
    for (size_t i = 0; i < EXT2_CACHE_SLOTS; ++i) {
        if (g_ext2.cache[i].valid && g_ext2.cache[i].block_num == block_num) {
            g_ext2.cache[i].last_use = ++g_ext2.cache_clock;
            if (writable) {
                g_ext2.cache[i].dirty = true;
            }
            return g_ext2.cache[i].data;
        }
        if (!g_ext2.cache[i].valid) {
            victim = i;
            oldest = 0;
            break;
        }
        if (g_ext2.cache[i].last_use < oldest) {
            oldest = g_ext2.cache[i].last_use;
            victim = i;
        }
    }

    if (g_ext2.cache[victim].valid) {
        if (flush_cache_slot(victim) != 0) {
            return NULL;
        }
    }
    if (g_ext2.cache[victim].data == NULL) {
        return NULL;
    }
    if (storage_read(offset, g_ext2.cache[victim].data, g_ext2.block_size) != 0) {
        return NULL;
    }

    g_ext2.cache[victim].valid = true;
    g_ext2.cache[victim].dirty = writable;
    g_ext2.cache[victim].block_num = block_num;
    g_ext2.cache[victim].last_use = ++g_ext2.cache_clock;
    return g_ext2.cache[victim].data;
}

static uint64_t inode_file_size(const struct ext2_inode* inode) {
    uint64_t size = inode->i_size;
    if ((inode->i_mode & FS_S_IFMT) == FS_S_IFREG) {
        size |= ((uint64_t)inode->i_dir_acl << 32);
    }
    return size;
}

static bool ext2_internal_path(const char* path, const char** internal_out) {
    return ext2_internal_path_for_mount(g_ext2_current, path, internal_out);
}

static uint8_t ext2_mode_to_file_type(uint32_t mode) {
    switch (mode & FS_S_IFMT) {
        case FS_S_IFREG:
            return EXT2_FT_REG_FILE;
        case FS_S_IFDIR:
            return EXT2_FT_DIR;
        case FS_S_IFCHR:
            return EXT2_FT_CHRDEV;
        case FS_S_IFBLK:
            return EXT2_FT_BLKDEV;
        case FS_S_IFIFO:
            return EXT2_FT_FIFO;
        case FS_S_IFLNK:
            return EXT2_FT_SYMLINK;
        case FS_S_IFSOCK:
            return EXT2_FT_SOCK;
        default:
            return EXT2_FT_UNKNOWN;
    }
}

static const uint8_t* block_ptr(uint32_t block_num) {
    return cache_block_ptr(block_num, false);
}

static uint8_t* block_ptr_mut(uint32_t block_num) {
    return cache_block_ptr(block_num, true);
}

static int read_group_desc(uint32_t group, struct ext2_group_desc* out) {
    if (!g_ext2.mounted || out == NULL || group >= g_ext2.group_count) {
        return -EINVAL;
    }

    uint64_t table_off = (g_ext2.block_size == 1024u) ? 2048u : g_ext2.block_size;
    uint64_t offset = table_off + (uint64_t)group * sizeof(struct ext2_group_desc);
    if (offset + sizeof(struct ext2_group_desc) > g_ext2.size) {
        return -EINVAL;
    }

    return storage_read(offset, out, sizeof(*out));
}

static int write_group_desc(uint32_t group, const struct ext2_group_desc* desc) {
    if (!g_ext2.mounted || g_ext2.read_only || desc == NULL || group >= g_ext2.group_count) {
        return desc == NULL ? -EINVAL : -EROFS;
    }

    uint64_t table_off = (g_ext2.block_size == 1024u) ? 2048u : g_ext2.block_size;
    uint64_t offset = table_off + (uint64_t)group * sizeof(struct ext2_group_desc);
    if (offset + sizeof(struct ext2_group_desc) > g_ext2.size) {
        return -EINVAL;
    }

    return storage_write(offset, desc, sizeof(*desc));
}

static bool bitmap_test(const uint8_t* bitmap, uint32_t index) {
    return (bitmap[index / 8u] & (uint8_t)(1u << (index % 8u))) != 0u;
}

static void bitmap_set(uint8_t* bitmap, uint32_t index, bool used) {
    uint8_t mask = (uint8_t)(1u << (index % 8u));
    if (used) {
        bitmap[index / 8u] |= mask;
    } else {
        bitmap[index / 8u] &= (uint8_t)~mask;
    }
}

static uint32_t blocks_in_group(uint32_t group) {
    uint32_t first = group * g_ext2.blocks_per_group;
    if (first >= g_ext2.blocks_count) {
        return 0;
    }
    uint32_t remain = g_ext2.blocks_count - first;
    return (remain < g_ext2.blocks_per_group) ? remain : g_ext2.blocks_per_group;
}

static uint32_t inodes_in_group(uint32_t group) {
    uint32_t first = group * g_ext2.inodes_per_group;
    if (first >= g_ext2.inodes_count) {
        return 0;
    }
    uint32_t remain = g_ext2.inodes_count - first;
    return (remain < g_ext2.inodes_per_group) ? remain : g_ext2.inodes_per_group;
}

static int alloc_block(uint32_t preferred_group, uint32_t* out) {
    if (out == NULL) {
        return -EINVAL;
    }
    if (g_ext2.read_only) {
        return -EROFS;
    }

    if (g_ext2.superblock.s_free_blocks_count == 0u) {
        return -ENOSPC;
    }

    for (uint32_t pass = 0; pass < g_ext2.group_count; ++pass) {
        uint32_t group = (preferred_group + pass) % g_ext2.group_count;
        struct ext2_group_desc desc;
        int gr = read_group_desc(group, &desc);
        if (gr != 0) {
            return gr;
        }
        if (desc.bg_free_blocks_count == 0u) {
            continue;
        }

        uint8_t* bitmap = block_ptr_mut(desc.bg_block_bitmap);
        if (bitmap == NULL) {
            return -EINVAL;
        }

        uint32_t count = blocks_in_group(group);
        for (uint32_t bit = 0; bit < count; ++bit) {
            uint32_t block_num = group * g_ext2.blocks_per_group + bit;
            if (block_num < g_ext2.first_data_block || block_num >= g_ext2.blocks_count) {
                continue;
            }
            if (bitmap_test(bitmap, bit)) {
                continue;
            }

            bitmap_set(bitmap, bit, true);
            desc.bg_free_blocks_count--;
            g_ext2.superblock.s_free_blocks_count--;
            int wr = write_group_desc(group, &desc);
            if (wr != 0) {
                return wr;
            }
            wr = write_superblock();
            if (wr != 0) {
                return wr;
            }
            uint8_t* block = block_ptr_mut(block_num);
            if (block == NULL) {
                return -EINVAL;
            }
            memset(block, 0, g_ext2.block_size);
            *out = block_num;
            return 0;
        }
    }

    return -ENOSPC;
}

static int free_block(uint32_t block_num) {
    if (block_num == 0) {
        return 0;
    }
    if (g_ext2.read_only) {
        return -EROFS;
    }
    if (block_num < g_ext2.first_data_block || block_num >= g_ext2.blocks_count) {
        return -EINVAL;
    }

    uint32_t group = block_num / g_ext2.blocks_per_group;
    uint32_t bit = block_num % g_ext2.blocks_per_group;
    struct ext2_group_desc desc;
    int gr = read_group_desc(group, &desc);
    if (gr != 0) {
        return gr;
    }
    uint8_t* bitmap = block_ptr_mut(desc.bg_block_bitmap);
    if (bitmap == NULL) {
        return -EINVAL;
    }
    if (!bitmap_test(bitmap, bit)) {
        return 0;
    }

    bitmap_set(bitmap, bit, false);
    desc.bg_free_blocks_count++;
    g_ext2.superblock.s_free_blocks_count++;
    int wr = write_group_desc(group, &desc);
    if (wr != 0) {
        return wr;
    }
    return write_superblock();
}

static int alloc_inode(uint32_t preferred_group, uint32_t mode, uint32_t* out) {
    if (out == NULL) {
        return -EINVAL;
    }
    if (g_ext2.read_only) {
        return -EROFS;
    }

    if (g_ext2.superblock.s_free_inodes_count == 0u) {
        return -ENOSPC;
    }

    for (uint32_t pass = 0; pass < g_ext2.group_count; ++pass) {
        uint32_t group = (preferred_group + pass) % g_ext2.group_count;
        struct ext2_group_desc desc;
        int gr = read_group_desc(group, &desc);
        if (gr != 0) {
            return gr;
        }
        if (desc.bg_free_inodes_count == 0u) {
            continue;
        }

        uint8_t* bitmap = block_ptr_mut(desc.bg_inode_bitmap);
        if (bitmap == NULL) {
            return -EINVAL;
        }

        uint32_t count = inodes_in_group(group);
        for (uint32_t bit = 0; bit < count; ++bit) {
            uint32_t inode_num = group * g_ext2.inodes_per_group + bit + 1u;
            if (inode_num < g_ext2.first_ino && inode_num != EXT2_ROOT_INO) {
                continue;
            }
            if (bitmap_test(bitmap, bit)) {
                continue;
            }

            bitmap_set(bitmap, bit, true);
            desc.bg_free_inodes_count--;
            if ((mode & FS_S_IFMT) == FS_S_IFDIR) {
                desc.bg_used_dirs_count++;
            }
            g_ext2.superblock.s_free_inodes_count--;
            int wr = write_group_desc(group, &desc);
            if (wr != 0) {
                return wr;
            }
            wr = write_superblock();
            if (wr != 0) {
                return wr;
            }
            *out = inode_num;
            return 0;
        }
    }

    return -ENOSPC;
}

static int free_inode_bitmap(uint32_t inode_num, uint32_t mode) {
    if (inode_num == 0) {
        return 0;
    }
    if (g_ext2.read_only) {
        return -EROFS;
    }
    if (inode_num > g_ext2.inodes_count) {
        return -EINVAL;
    }

    uint32_t index = inode_num - 1u;
    uint32_t group = index / g_ext2.inodes_per_group;
    uint32_t bit = index % g_ext2.inodes_per_group;
    struct ext2_group_desc desc;
    int gr = read_group_desc(group, &desc);
    if (gr != 0) {
        return gr;
    }
    uint8_t* bitmap = block_ptr_mut(desc.bg_inode_bitmap);
    if (bitmap == NULL) {
        return -EINVAL;
    }
    if (!bitmap_test(bitmap, bit)) {
        return 0;
    }

    bitmap_set(bitmap, bit, false);
    desc.bg_free_inodes_count++;
    if ((mode & FS_S_IFMT) == FS_S_IFDIR && desc.bg_used_dirs_count > 0u) {
        desc.bg_used_dirs_count--;
    }
    g_ext2.superblock.s_free_inodes_count++;
    int wr = write_group_desc(group, &desc);
    if (wr != 0) {
        return wr;
    }
    return write_superblock();
}

static int inode_disk_offset(uint32_t inode_num, uint64_t* offset_out) {
    if (!g_ext2.mounted || offset_out == NULL || inode_num == 0) {
        return -EINVAL;
    }

    uint32_t index = inode_num - 1u;
    uint32_t group = index / g_ext2.inodes_per_group;
    uint32_t idx_in_group = index % g_ext2.inodes_per_group;

    struct ext2_group_desc desc;
    int gr = read_group_desc(group, &desc);
    if (gr != 0) {
        return gr;
    }

    uint64_t table_off = (uint64_t)desc.bg_inode_table * g_ext2.block_size;
    uint64_t inode_off = table_off + (uint64_t)idx_in_group * g_ext2.inode_size;
    if (inode_off + sizeof(struct ext2_inode) > g_ext2.size) {
        return -EINVAL;
    }

    *offset_out = inode_off;
    return 0;
}

static int read_inode(uint32_t inode_num, struct ext2_inode* out) {
    if (out == NULL) {
        return -EINVAL;
    }

    uint64_t inode_off = 0;
    int or = inode_disk_offset(inode_num, &inode_off);
    if (or != 0) {
        return or;
    }

    memset(out, 0, sizeof(*out));
    return storage_read(inode_off, out, min_int((int)sizeof(*out), (int)g_ext2.inode_size));
}

static int write_inode(uint32_t inode_num, const struct ext2_inode* inode) {
    if (inode == NULL || g_ext2.read_only) {
        return inode == NULL ? -EINVAL : -EROFS;
    }

    uint64_t inode_off = 0;
    int or = inode_disk_offset(inode_num, &inode_off);
    if (or != 0) {
        return or;
    }

    return storage_write(inode_off, inode, min_int((int)sizeof(*inode), (int)g_ext2.inode_size));
}

static int read_indirect_ptr(uint32_t block_num, uint32_t index, uint32_t* out) {
    if (out == NULL) {
        return -EINVAL;
    }
    if (block_num == 0) {
        *out = 0;
        return 0;
    }

    uint32_t ptrs_per_block = g_ext2.block_size / sizeof(uint32_t);
    if (index >= ptrs_per_block) {
        return -EINVAL;
    }

    const uint8_t* block = block_ptr(block_num);
    if (block == NULL) {
        return -EINVAL;
    }

    memcpy(out, block + (uint64_t)index * sizeof(uint32_t), sizeof(*out));
    return 0;
}

static int write_indirect_ptr(uint32_t block_num, uint32_t index, uint32_t value) {
    uint32_t ptrs_per_block = g_ext2.block_size / sizeof(uint32_t);
    if (block_num == 0 || index >= ptrs_per_block || g_ext2.read_only) {
        return g_ext2.read_only ? -EROFS : -EINVAL;
    }

    uint8_t* block = block_ptr_mut(block_num);
    if (block == NULL) {
        return -EINVAL;
    }

    memcpy(block + (uint64_t)index * sizeof(uint32_t), &value, sizeof(value));
    return 0;
}

static int alloc_inode_owned_block(struct ext2_inode* inode, uint32_t* out) {
    if (inode == NULL || out == NULL) {
        return -EINVAL;
    }

    int r = alloc_block(0, out);
    if (r != 0) {
        return r;
    }
    inode->i_blocks += g_ext2.block_size / 512u;
    return 0;
}

static int free_inode_owned_block(struct ext2_inode* inode, uint32_t block_num) {
    if (inode == NULL || block_num == 0) {
        return 0;
    }
    int r = free_block(block_num);
    if (r != 0) {
        return r;
    }
    uint32_t sectors = g_ext2.block_size / 512u;
    inode->i_blocks = (inode->i_blocks > sectors) ? inode->i_blocks - sectors : 0u;
    return 0;
}

static int inode_block_number(const struct ext2_inode* inode, uint32_t logical_index, uint32_t* out) {
    if (inode == NULL || out == NULL) {
        return -EINVAL;
    }

    uint32_t ptrs_per_block = g_ext2.block_size / sizeof(uint32_t);
    if (logical_index < EXT2_NDIR_BLOCKS) {
        *out = inode->i_block[logical_index];
        return 0;
    }

    logical_index -= EXT2_NDIR_BLOCKS;
    if (logical_index < ptrs_per_block) {
        return read_indirect_ptr(inode->i_block[EXT2_IND_BLOCK], logical_index, out);
    }

    logical_index -= ptrs_per_block;
    uint64_t per_double = (uint64_t)ptrs_per_block * (uint64_t)ptrs_per_block;
    if ((uint64_t)logical_index < per_double) {
        uint32_t outer = logical_index / ptrs_per_block;
        uint32_t inner = logical_index % ptrs_per_block;
        uint32_t block = 0;
        int r = read_indirect_ptr(inode->i_block[EXT2_DIND_BLOCK], outer, &block);
        if (r != 0) {
            return r;
        }
        return read_indirect_ptr(block, inner, out);
    }

    logical_index -= (uint32_t)per_double;
    uint64_t per_triple = per_double * (uint64_t)ptrs_per_block;
    if ((uint64_t)logical_index < per_triple) {
        uint32_t outer = logical_index / (uint32_t)per_double;
        uint32_t rem = logical_index % (uint32_t)per_double;
        uint32_t middle = rem / ptrs_per_block;
        uint32_t inner = rem % ptrs_per_block;
        uint32_t block = 0;
        uint32_t block2 = 0;
        int r = read_indirect_ptr(inode->i_block[EXT2_TIND_BLOCK], outer, &block);
        if (r != 0) {
            return r;
        }
        r = read_indirect_ptr(block, middle, &block2);
        if (r != 0) {
            return r;
        }
        return read_indirect_ptr(block2, inner, out);
    }

    return -EINVAL;
}

static int inode_block_number_alloc(struct ext2_inode* inode, uint32_t logical_index, bool allocate, uint32_t* out) {
    if (inode == NULL || out == NULL) {
        return -EINVAL;
    }

    uint32_t ptrs_per_block = g_ext2.block_size / sizeof(uint32_t);
    if (logical_index < EXT2_NDIR_BLOCKS) {
        if (inode->i_block[logical_index] == 0 && allocate) {
            uint32_t new_block = 0;
            int r = alloc_inode_owned_block(inode, &new_block);
            if (r != 0) {
                return r;
            }
            inode->i_block[logical_index] = new_block;
        }
        *out = inode->i_block[logical_index];
        return 0;
    }

    logical_index -= EXT2_NDIR_BLOCKS;
    if (logical_index < ptrs_per_block) {
        if (inode->i_block[EXT2_IND_BLOCK] == 0) {
            if (!allocate) {
                *out = 0;
                return 0;
            }
            uint32_t new_block = 0;
            int r = alloc_inode_owned_block(inode, &new_block);
            if (r != 0) {
                return r;
            }
            inode->i_block[EXT2_IND_BLOCK] = new_block;
        }

        uint32_t block = 0;
        int r = read_indirect_ptr(inode->i_block[EXT2_IND_BLOCK], logical_index, &block);
        if (r != 0) {
            return r;
        }
        if (block == 0 && allocate) {
            r = alloc_inode_owned_block(inode, &block);
            if (r != 0) {
                return r;
            }
            r = write_indirect_ptr(inode->i_block[EXT2_IND_BLOCK], logical_index, block);
            if (r != 0) {
                return r;
            }
        }
        *out = block;
        return 0;
    }

    logical_index -= ptrs_per_block;
    uint64_t per_double = (uint64_t)ptrs_per_block * (uint64_t)ptrs_per_block;
    if ((uint64_t)logical_index < per_double) {
        if (inode->i_block[EXT2_DIND_BLOCK] == 0) {
            if (!allocate) {
                *out = 0;
                return 0;
            }
            uint32_t new_block = 0;
            int r = alloc_inode_owned_block(inode, &new_block);
            if (r != 0) {
                return r;
            }
            inode->i_block[EXT2_DIND_BLOCK] = new_block;
        }

        uint32_t outer = logical_index / ptrs_per_block;
        uint32_t inner = logical_index % ptrs_per_block;
        uint32_t block = 0;
        int r = read_indirect_ptr(inode->i_block[EXT2_DIND_BLOCK], outer, &block);
        if (r != 0) {
            return r;
        }
        if (block == 0 && allocate) {
            r = alloc_inode_owned_block(inode, &block);
            if (r != 0) {
                return r;
            }
            r = write_indirect_ptr(inode->i_block[EXT2_DIND_BLOCK], outer, block);
            if (r != 0) {
                return r;
            }
        }
        if (block == 0) {
            *out = 0;
            return 0;
        }

        uint32_t data = 0;
        r = read_indirect_ptr(block, inner, &data);
        if (r != 0) {
            return r;
        }
        if (data == 0 && allocate) {
            r = alloc_inode_owned_block(inode, &data);
            if (r != 0) {
                return r;
            }
            r = write_indirect_ptr(block, inner, data);
            if (r != 0) {
                return r;
            }
        }
        *out = data;
        return 0;
    }

    logical_index -= (uint32_t)per_double;
    uint64_t per_triple = per_double * (uint64_t)ptrs_per_block;
    if ((uint64_t)logical_index >= per_triple) {
        return -EINVAL;
    }

    if (inode->i_block[EXT2_TIND_BLOCK] == 0) {
        if (!allocate) {
            *out = 0;
            return 0;
        }
        uint32_t new_block = 0;
        int r = alloc_inode_owned_block(inode, &new_block);
        if (r != 0) {
            return r;
        }
        inode->i_block[EXT2_TIND_BLOCK] = new_block;
    }

    uint32_t outer = logical_index / (uint32_t)per_double;
    uint32_t rem = logical_index % (uint32_t)per_double;
    uint32_t middle = rem / ptrs_per_block;
    uint32_t inner = rem % ptrs_per_block;
    uint32_t block = 0;
    int r = read_indirect_ptr(inode->i_block[EXT2_TIND_BLOCK], outer, &block);
    if (r != 0) {
        return r;
    }
    if (block == 0 && allocate) {
        r = alloc_inode_owned_block(inode, &block);
        if (r != 0) {
            return r;
        }
        r = write_indirect_ptr(inode->i_block[EXT2_TIND_BLOCK], outer, block);
        if (r != 0) {
            return r;
        }
    }
    if (block == 0) {
        *out = 0;
        return 0;
    }

    uint32_t block2 = 0;
    r = read_indirect_ptr(block, middle, &block2);
    if (r != 0) {
        return r;
    }
    if (block2 == 0 && allocate) {
        r = alloc_inode_owned_block(inode, &block2);
        if (r != 0) {
            return r;
        }
        r = write_indirect_ptr(block, middle, block2);
        if (r != 0) {
            return r;
        }
    }
    if (block2 == 0) {
        *out = 0;
        return 0;
    }

    uint32_t data = 0;
    r = read_indirect_ptr(block2, inner, &data);
    if (r != 0) {
        return r;
    }
    if (data == 0 && allocate) {
        r = alloc_inode_owned_block(inode, &data);
        if (r != 0) {
            return r;
        }
        r = write_indirect_ptr(block2, inner, data);
        if (r != 0) {
            return r;
        }
    }
    *out = data;
    return 0;
}

static bool indirect_block_empty(uint32_t block_num) {
    if (block_num == 0) {
        return true;
    }
    const uint8_t* block = block_ptr(block_num);
    if (block == NULL) {
        return false;
    }

    uint32_t ptrs_per_block = g_ext2.block_size / sizeof(uint32_t);
    for (uint32_t i = 0; i < ptrs_per_block; ++i) {
        uint32_t ptr = 0;
        memcpy(&ptr, block + (uint64_t)i * sizeof(uint32_t), sizeof(ptr));
        if (ptr != 0) {
            return false;
        }
    }
    return true;
}

static int clear_inode_block_mapping(struct ext2_inode* inode, uint32_t logical_index) {
    if (inode == NULL) {
        return -EINVAL;
    }

    uint32_t ptrs_per_block = g_ext2.block_size / sizeof(uint32_t);
    if (logical_index < EXT2_NDIR_BLOCKS) {
        uint32_t block = inode->i_block[logical_index];
        inode->i_block[logical_index] = 0;
        return free_inode_owned_block(inode, block);
    }

    logical_index -= EXT2_NDIR_BLOCKS;
    if (logical_index < ptrs_per_block) {
        uint32_t ind = inode->i_block[EXT2_IND_BLOCK];
        if (ind == 0) {
            return 0;
        }
        uint32_t block = 0;
        int r = read_indirect_ptr(ind, logical_index, &block);
        if (r != 0) {
            return r;
        }
        r = write_indirect_ptr(ind, logical_index, 0);
        if (r != 0) {
            return r;
        }
        r = free_inode_owned_block(inode, block);
        if (r != 0) {
            return r;
        }
        if (indirect_block_empty(ind)) {
            inode->i_block[EXT2_IND_BLOCK] = 0;
            return free_inode_owned_block(inode, ind);
        }
        return 0;
    }

    logical_index -= ptrs_per_block;
    uint64_t per_double = (uint64_t)ptrs_per_block * (uint64_t)ptrs_per_block;
    if ((uint64_t)logical_index < per_double) {
        uint32_t dind = inode->i_block[EXT2_DIND_BLOCK];
        if (dind == 0) {
            return 0;
        }
        uint32_t outer = logical_index / ptrs_per_block;
        uint32_t inner = logical_index % ptrs_per_block;
        uint32_t ind = 0;
        int r = read_indirect_ptr(dind, outer, &ind);
        if (r != 0 || ind == 0) {
            return r;
        }
        uint32_t block = 0;
        r = read_indirect_ptr(ind, inner, &block);
        if (r != 0) {
            return r;
        }
        r = write_indirect_ptr(ind, inner, 0);
        if (r != 0) {
            return r;
        }
        r = free_inode_owned_block(inode, block);
        if (r != 0) {
            return r;
        }
        if (indirect_block_empty(ind)) {
            r = write_indirect_ptr(dind, outer, 0);
            if (r != 0) {
                return r;
            }
            r = free_inode_owned_block(inode, ind);
            if (r != 0) {
                return r;
            }
        }
        if (indirect_block_empty(dind)) {
            inode->i_block[EXT2_DIND_BLOCK] = 0;
            return free_inode_owned_block(inode, dind);
        }
        return 0;
    }

    logical_index -= (uint32_t)per_double;
    uint64_t per_triple = per_double * (uint64_t)ptrs_per_block;
    if ((uint64_t)logical_index >= per_triple) {
        return -EINVAL;
    }

    uint32_t tind = inode->i_block[EXT2_TIND_BLOCK];
    if (tind == 0) {
        return 0;
    }
    uint32_t outer = logical_index / (uint32_t)per_double;
    uint32_t rem = logical_index % (uint32_t)per_double;
    uint32_t middle = rem / ptrs_per_block;
    uint32_t inner = rem % ptrs_per_block;
    uint32_t dind = 0;
    int r = read_indirect_ptr(tind, outer, &dind);
    if (r != 0 || dind == 0) {
        return r;
    }
    uint32_t ind = 0;
    r = read_indirect_ptr(dind, middle, &ind);
    if (r != 0 || ind == 0) {
        return r;
    }
    uint32_t block = 0;
    r = read_indirect_ptr(ind, inner, &block);
    if (r != 0) {
        return r;
    }
    r = write_indirect_ptr(ind, inner, 0);
    if (r != 0) {
        return r;
    }
    r = free_inode_owned_block(inode, block);
    if (r != 0) {
        return r;
    }
    if (indirect_block_empty(ind)) {
        r = write_indirect_ptr(dind, middle, 0);
        if (r != 0) {
            return r;
        }
        r = free_inode_owned_block(inode, ind);
        if (r != 0) {
            return r;
        }
    }
    if (indirect_block_empty(dind)) {
        r = write_indirect_ptr(tind, outer, 0);
        if (r != 0) {
            return r;
        }
        r = free_inode_owned_block(inode, dind);
        if (r != 0) {
            return r;
        }
    }
    if (indirect_block_empty(tind)) {
        inode->i_block[EXT2_TIND_BLOCK] = 0;
        return free_inode_owned_block(inode, tind);
    }
    return 0;
}

static int free_inode_blocks_from(struct ext2_inode* inode, size_t old_size, size_t new_size) {
    if (inode == NULL || new_size >= old_size) {
        return 0;
    }

    uint32_t old_blocks = (uint32_t)((old_size + g_ext2.block_size - 1u) / g_ext2.block_size);
    uint32_t keep_blocks = (uint32_t)((new_size + g_ext2.block_size - 1u) / g_ext2.block_size);
    for (uint32_t logical = keep_blocks; logical < old_blocks; ++logical) {
        int r = clear_inode_block_mapping(inode, logical);
        if (r != 0) {
            return r;
        }
    }
    return 0;
}

static int read_inode_bytes(const struct ext2_inode* inode, size_t file_size, size_t offset, void* buf, size_t count) {
    if (buf == NULL) {
        return -EINVAL;
    }
    if (offset >= file_size) {
        return 0;
    }

    size_t total = file_size - offset;
    if (count < total) {
        total = count;
    }

    size_t done = 0;
    while (done < total) {
        size_t current = offset + done;
        uint32_t logical_block = (uint32_t)(current / g_ext2.block_size);
        size_t block_off = current % g_ext2.block_size;
        size_t chunk = total - done;
        size_t block_remain = g_ext2.block_size - block_off;
        if (chunk > block_remain) {
            chunk = block_remain;
        }

        uint32_t phys = 0;
        int br = inode_block_number(inode, logical_block, &phys);
        if (br != 0) {
            return br;
        }
        if (phys == 0) {
            memset((uint8_t*)buf + done, 0, chunk);
        } else {
            const uint8_t* block = block_ptr(phys);
            if (block == NULL) {
                return -EINVAL;
            }
            memcpy((uint8_t*)buf + done, block + block_off, chunk);
        }
        done += chunk;
    }

    return (int)done;
}

static int write_inode_span(struct ext2_inode* inode, size_t offset, const void* buf, size_t count) {
    if (inode == NULL || buf == NULL) {
        return -EINVAL;
    }

    size_t done = 0;
    while (done < count) {
        size_t current = offset + done;
        uint32_t logical_block = (uint32_t)(current / g_ext2.block_size);
        size_t block_off = current % g_ext2.block_size;
        size_t chunk = count - done;
        size_t block_remain = g_ext2.block_size - block_off;
        if (chunk > block_remain) {
            chunk = block_remain;
        }

        uint32_t phys = 0;
        int br = inode_block_number_alloc(inode, logical_block, true, &phys);
        if (br != 0) {
            return br;
        }
        uint8_t* block = block_ptr_mut(phys);
        if (block == NULL) {
            return -ENOSPC;
        }

        memcpy(block + block_off, (const uint8_t*)buf + done, chunk);
        done += chunk;
    }

    return (int)done;
}

static int zero_inode_span(struct ext2_inode* inode, size_t offset, size_t count) {
    if (inode == NULL) {
        return -EINVAL;
    }

    uint8_t zeroes[256];
    memset(zeroes, 0, sizeof(zeroes));

    size_t done = 0;
    while (done < count) {
        size_t chunk = count - done;
        if (chunk > sizeof(zeroes)) {
            chunk = sizeof(zeroes);
        }
        int wr = write_inode_span(inode, offset + done, zeroes, chunk);
        if (wr < 0) {
            return wr;
        }
        done += (size_t)wr;
    }

    return (int)done;
}

static void set_inode_file_size(struct ext2_inode* inode, uint64_t size) {
    inode->i_size = (uint32_t)size;
    if ((inode->i_mode & FS_S_IFMT) == FS_S_IFREG) {
        inode->i_dir_acl = (uint32_t)(size >> 32);
    }
}

static int finish_mutation(int result) {
    if (result != 0) {
        return result;
    }
    return flush_block_cache();
}

static uint8_t ext2_ft_to_dtype(uint8_t file_type, uint32_t mode) {
    switch (file_type) {
        case EXT2_FT_REG_FILE:
            return FS_DT_REG;
        case EXT2_FT_DIR:
            return FS_DT_DIR;
        case EXT2_FT_CHRDEV:
            return FS_DT_CHR;
        case EXT2_FT_BLKDEV:
            return FS_DT_BLK;
        case EXT2_FT_FIFO:
            return FS_DT_FIFO;
        case EXT2_FT_SYMLINK:
            return FS_DT_LNK;
        case EXT2_FT_UNKNOWN:
        default:
            return fs_mode_to_dtype(mode);
    }
}

static int find_child_inode(uint32_t dir_ino, const char* name, uint32_t* child_out, uint8_t* file_type_out) {
    struct ext2_inode dir_inode;
    int ir = read_inode(dir_ino, &dir_inode);
    if (ir != 0) {
        return ir;
    }
    if ((dir_inode.i_mode & FS_S_IFMT) != FS_S_IFDIR) {
        return -ENOENT;
    }

    size_t dir_size = (size_t)inode_file_size(&dir_inode);
    size_t offset = 0;
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&dir_inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head)) {
            return -EINVAL;
        }
        if (head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            return -EINVAL;
        }

        if (head.inode != 0 && head.name_len != 0 && head.name_len <= head.rec_len - sizeof(head)) {
            char entry_name[EXT2_NAME_LEN + 1u];
            rr = read_inode_bytes(&dir_inode, dir_size, offset + sizeof(head), entry_name, head.name_len);
            if (rr < 0) {
                return rr;
            }
            entry_name[head.name_len] = '\0';

            if (strcmp(entry_name, name) == 0) {
                if (child_out != NULL) {
                    *child_out = head.inode;
                }
                if (file_type_out != NULL) {
                    *file_type_out = head.file_type;
                }
                return 0;
            }
        }

        offset += head.rec_len;
    }

    return -ENOENT;
}

static int ext2_parent_and_name(const char* path, char* parent_out, size_t parent_len, char* name_out, size_t name_len) {
    if (path == NULL || parent_out == NULL || name_out == NULL || parent_len == 0 || name_len == 0) {
        return -EINVAL;
    }
    if (!ext2_owns_path(path)) {
        return -ENOENT;
    }

    size_t len = strlen(path);
    size_t mount_len = g_ext2.mount_path_len;
    while (len > mount_len && path[len - 1u] == '/') {
        --len;
    }
    if (len <= mount_len) {
        return -EINVAL;
    }

    size_t slash = len;
    while (slash > 0 && path[slash - 1u] != '/') {
        --slash;
    }
    if (slash <= mount_len || slash >= len) {
        return -EINVAL;
    }

    size_t nlen = len - slash;
    if (nlen == 0 || nlen > EXT2_NAME_LEN || nlen + 1u > name_len) {
        return -EINVAL;
    }
    memcpy(name_out, path + slash, nlen);
    name_out[nlen] = '\0';
    if (strcmp(name_out, ".") == 0 || strcmp(name_out, "..") == 0) {
        return -EINVAL;
    }

    size_t plen = slash - 1u;
    if (plen < mount_len) {
        plen = mount_len;
    }
    if (plen + 1u > parent_len) {
        return -EINVAL;
    }
    memcpy(parent_out, path, plen);
    parent_out[plen] = '\0';
    return 0;
}

static int lookup_inode_number(const char* path, uint32_t* inode_out) {
    struct fs_entry entry;
    int r = ext2_lookup(path, &entry);
    if (r != 0) {
        return r;
    }
    if (inode_out != NULL) {
        *inode_out = entry.inode;
    }
    return 0;
}

static int lookup_parent_inode(const char* path, uint32_t* parent_out, char* name_out, size_t name_len) {
    char parent[FS_MAX_PATH];
    int r = ext2_parent_and_name(path, parent, sizeof(parent), name_out, name_len);
    if (r != 0) {
        return r;
    }
    return lookup_inode_number(parent, parent_out);
}

static int write_dirent(struct ext2_inode* dir, size_t offset, uint32_t inode_num, uint16_t rec_len, const char* name, uint8_t file_type) {
    size_t name_len = strlen(name);
    if (name_len > EXT2_NAME_LEN || rec_len < ext2_dir_rec_len(name_len)) {
        return -EINVAL;
    }

    struct ext2_dirent_head head;
    head.inode = inode_num;
    head.rec_len = rec_len;
    head.name_len = (uint8_t)name_len;
    head.file_type = file_type;

    int wr = write_inode_span(dir, offset, &head, sizeof(head));
    if (wr < (int)sizeof(head)) {
        return wr < 0 ? wr : -EINVAL;
    }
    wr = write_inode_span(dir, offset + sizeof(head), name, name_len);
    if (wr < (int)name_len) {
        return wr < 0 ? wr : -EINVAL;
    }
    return 0;
}

static int find_dirent(uint32_t dir_ino, const char* name, size_t* offset_out, struct ext2_dirent_head* head_out,
                       size_t* prev_offset_out, struct ext2_dirent_head* prev_head_out) {
    struct ext2_inode dir_inode;
    int ir = read_inode(dir_ino, &dir_inode);
    if (ir != 0) {
        return ir;
    }
    if ((dir_inode.i_mode & FS_S_IFMT) != FS_S_IFDIR) {
        return -ENOTDIR;
    }

    size_t dir_size = (size_t)inode_file_size(&dir_inode);
    size_t offset = 0;
    size_t prev_offset = 0;
    bool have_prev = false;
    struct ext2_dirent_head prev_head;
    memset(&prev_head, 0, sizeof(prev_head));
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&dir_inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head)) {
            return -EINVAL;
        }
        if (head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            return -EINVAL;
        }

        if (head.inode != 0 && head.name_len != 0 && head.name_len <= head.rec_len - sizeof(head)) {
            char entry_name[EXT2_NAME_LEN + 1u];
            rr = read_inode_bytes(&dir_inode, dir_size, offset + sizeof(head), entry_name, head.name_len);
            if (rr < 0) {
                return rr;
            }
            entry_name[head.name_len] = '\0';
            if (strcmp(entry_name, name) == 0) {
                if (offset_out != NULL) {
                    *offset_out = offset;
                }
                if (head_out != NULL) {
                    *head_out = head;
                }
                if (prev_offset_out != NULL) {
                    *prev_offset_out = have_prev ? prev_offset : offset;
                }
                if (prev_head_out != NULL) {
                    *prev_head_out = have_prev ? prev_head : head;
                }
                return 0;
            }
        }

        have_prev = true;
        prev_offset = offset;
        prev_head = head;
        offset += head.rec_len;
    }

    return -ENOENT;
}

static int add_dirent(uint32_t dir_ino, const char* name, uint32_t child_ino, uint8_t file_type) {
    if (name == NULL || name[0] == '\0' || strlen(name) > EXT2_NAME_LEN) {
        return -EINVAL;
    }
    if (find_child_inode(dir_ino, name, NULL, NULL) == 0) {
        return -EEXIST;
    }

    struct ext2_inode dir_inode;
    int ir = read_inode(dir_ino, &dir_inode);
    if (ir != 0) {
        return ir;
    }
    if ((dir_inode.i_mode & FS_S_IFMT) != FS_S_IFDIR) {
        return -ENOTDIR;
    }

    uint16_t need = ext2_dir_rec_len(strlen(name));
    size_t dir_size = (size_t)inode_file_size(&dir_inode);
    size_t offset = 0;
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&dir_inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head) || head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            return -EINVAL;
        }

        if (head.inode == 0 && head.rec_len >= need) {
            int wr = write_dirent(&dir_inode, offset, child_ino, head.rec_len, name, file_type);
            if (wr != 0) {
                return wr;
            }
            return write_inode(dir_ino, &dir_inode);
        }

        uint16_t ideal = ext2_dir_rec_len(head.name_len);
        if (head.inode != 0 && head.rec_len >= ideal + need) {
            uint16_t old_rec_len = head.rec_len;
            head.rec_len = ideal;
            int wr = write_inode_span(&dir_inode, offset, &head, sizeof(head));
            if (wr < (int)sizeof(head)) {
                return wr < 0 ? wr : -EINVAL;
            }
            wr = write_dirent(&dir_inode, offset + ideal, child_ino, (uint16_t)(old_rec_len - ideal), name, file_type);
            if (wr != 0) {
                return wr;
            }
            return write_inode(dir_ino, &dir_inode);
        }

        offset += head.rec_len;
    }

    size_t append = (dir_size + g_ext2.block_size - 1u) & ~(size_t)(g_ext2.block_size - 1u);
    int wr = write_dirent(&dir_inode, append, child_ino, (uint16_t)g_ext2.block_size, name, file_type);
    if (wr != 0) {
        return wr;
    }
    set_inode_file_size(&dir_inode, append + g_ext2.block_size);
    return write_inode(dir_ino, &dir_inode);
}

static int remove_dirent(uint32_t dir_ino, const char* name, uint32_t* child_out, uint8_t* file_type_out) {
    size_t offset = 0;
    size_t prev_offset = 0;
    struct ext2_dirent_head head;
    struct ext2_dirent_head prev_head;
    int r = find_dirent(dir_ino, name, &offset, &head, &prev_offset, &prev_head);
    if (r != 0) {
        return r;
    }

    struct ext2_inode dir_inode;
    r = read_inode(dir_ino, &dir_inode);
    if (r != 0) {
        return r;
    }

    if (child_out != NULL) {
        *child_out = head.inode;
    }
    if (file_type_out != NULL) {
        *file_type_out = head.file_type;
    }

    if (prev_offset != offset && prev_offset / g_ext2.block_size == offset / g_ext2.block_size) {
        prev_head.rec_len = (uint16_t)(prev_head.rec_len + head.rec_len);
        int wr = write_inode_span(&dir_inode, prev_offset, &prev_head, sizeof(prev_head));
        if (wr < (int)sizeof(prev_head)) {
            return wr < 0 ? wr : -EINVAL;
        }
    } else {
        head.inode = 0;
        int wr = write_inode_span(&dir_inode, offset, &head, sizeof(head));
        if (wr < (int)sizeof(head)) {
            return wr < 0 ? wr : -EINVAL;
        }
    }

    return write_inode(dir_ino, &dir_inode);
}

static bool dir_is_empty(uint32_t dir_ino) {
    struct ext2_inode dir_inode;
    if (read_inode(dir_ino, &dir_inode) != 0 || (dir_inode.i_mode & FS_S_IFMT) != FS_S_IFDIR) {
        return false;
    }

    size_t dir_size = (size_t)inode_file_size(&dir_inode);
    size_t offset = 0;
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&dir_inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head) || head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            return false;
        }

        if (head.inode != 0 && head.name_len != 0) {
            char name[EXT2_NAME_LEN + 1u];
            rr = read_inode_bytes(&dir_inode, dir_size, offset + sizeof(head), name, head.name_len);
            if (rr < 0) {
                return false;
            }
            name[head.name_len] = '\0';
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                return false;
            }
        }

        offset += head.rec_len;
    }

    return true;
}

static int fill_entry(const char* path, uint32_t inode_num, struct fs_entry* out) {
    struct ext2_inode inode;
    int ir = read_inode(inode_num, &inode);
    if (ir != 0) {
        return ir;
    }

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        strncpy(out->path, path, sizeof(out->path));
        out->path[sizeof(out->path) - 1] = '\0';
        out->backend = FS_BACKEND_EXT2;
        out->inode = inode_num;
        out->mode = inode.i_mode;
        out->size = (size_t)inode_file_size(&inode);
        out->read_only = g_ext2.read_only;
    }

    return 0;
}

static void release_block_cache(void) {
    release_mount_cache(&g_ext2);
}

static int ext2_build_mount(struct ext2_mount* mount, const char* mount_path, const struct ext2_storage_ops* ops, void* ctx,
                            size_t size, bool read_only) {
    if (mount == NULL || mount_path == NULL || mount_path[0] != '/' || ops == NULL || ops->read == NULL || size < 2048u) {
        return -EINVAL;
    }

    memset(mount, 0, sizeof(*mount));
    strncpy(mount->mount_path, mount_path, sizeof(mount->mount_path));
    mount->mount_path[sizeof(mount->mount_path) - 1] = '\0';
    mount->mount_path_len = strlen(mount->mount_path);
    if (mount->mount_path_len == 0 || mount->mount_path_len >= sizeof(mount->mount_path)) {
        memset(mount, 0, sizeof(*mount));
        return -EINVAL;
    }
    mount->ops = ops;
    mount->storage_ctx = ctx;
    mount->size = size;
    mount->read_only = read_only;
    mount->mounted = true;

    if (ops->read(ctx, 1024u, &mount->superblock, sizeof(mount->superblock)) != 0 || mount->superblock.s_magic != EXT2_SUPER_MAGIC) {
        memset(mount, 0, sizeof(*mount));
        return -EINVAL;
    }

    mount->block_size = 1024u << mount->superblock.s_log_block_size;
    mount->inodes_count = mount->superblock.s_inodes_count;
    mount->blocks_count = mount->superblock.s_blocks_count;
    mount->first_data_block = mount->superblock.s_first_data_block;
    mount->blocks_per_group = mount->superblock.s_blocks_per_group;
    mount->inodes_per_group = mount->superblock.s_inodes_per_group;
    mount->first_ino = (mount->superblock.s_first_ino != 0u) ? mount->superblock.s_first_ino : 11u;
    mount->inode_size = (mount->superblock.s_inode_size >= sizeof(struct ext2_inode)) ? mount->superblock.s_inode_size
                                                                                       : sizeof(struct ext2_inode);
    mount->group_count = (mount->blocks_count + mount->blocks_per_group - 1u) / mount->blocks_per_group;
    mount->mounted = (mount->block_size >= 1024u && mount->group_count != 0u && mount->inodes_per_group != 0u);
    if (!mount->mounted) {
        memset(mount, 0, sizeof(*mount));
        return -EINVAL;
    }

    for (size_t i = 0; i < EXT2_CACHE_SLOTS; ++i) {
        mount->cache[i].data = kmalloc(mount->block_size);
        if (mount->cache[i].data == NULL) {
            release_mount_cache(mount);
            memset(mount, 0, sizeof(*mount));
            return -ENOMEM;
        }
    }

    if (!read_only && (mount->superblock.s_state & EXT2_VALID_FS) != 0u) {
        mount->superblock.s_state &= (uint16_t)~EXT2_VALID_FS;
        if (ops->write == NULL || ops->write(ctx, 1024u, &mount->superblock, sizeof(mount->superblock)) != 0) {
            release_mount_cache(mount);
            memset(mount, 0, sizeof(*mount));
            return -EINVAL;
        }
    }

    return 0;
}

static void ext2_destroy_mount(struct ext2_mount* mount) {
    if (mount == NULL) {
        return;
    }

    struct ext2_mount* saved = g_ext2_current;
    g_ext2_current = mount;
    (void)ext2_sync_current(true);
    release_block_cache();
    g_ext2_current = saved;
    if (mount->ops == &g_ext2_file_ops) {
        memset(&mount->file_storage, 0, sizeof(mount->file_storage));
    }
    memset(mount, 0, sizeof(*mount));
}

int ext2_mount_storage_at(const char* mount_path, const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only) {
    struct ext2_mount mounted;
    int r = ext2_build_mount(&mounted, mount_path, ops, ctx, size, read_only);
    if (r != 0) {
        return r;
    }

    struct ext2_mount* slot = ext2_find_mount_by_exact_path(mount_path);
    if (slot == NULL) {
        slot = ext2_find_free_mount_slot();
    }
    if (slot == NULL) {
        release_mount_cache(&mounted);
        return -ENOMEM;
    }

    ext2_destroy_mount(slot);
    *slot = mounted;
    g_ext2_current = slot;
    return 0;
}

int ext2_mount_storage(const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only) {
    return ext2_mount_storage_at("/usr", ops, ctx, size, read_only);
}

int ext2_mount_image_at(const char* mount_path, const uint8_t* image, size_t size, bool read_only) {
    if (image == NULL) {
        struct ext2_mount* mount = ext2_find_mount_by_exact_path(mount_path);
        if (mount != NULL) {
            ext2_destroy_mount(mount);
        }
        return 0;
    }
    return ext2_mount_storage_at(mount_path, &g_ext2_mem_ops, (void*)(uintptr_t)image, size, read_only);
}

void ext2_mount_image(const uint8_t* image, size_t size, bool read_only) {
    (void)ext2_mount_image_at("/usr", image, size, read_only);
}

int ext2_mount_file_at(const char* mount_path, const struct fs_entry* image_file, bool read_only) {
    if (image_file == NULL || image_file->backend == FS_BACKEND_NONE || (image_file->mode & FS_S_IFMT) != FS_S_IFREG ||
        image_file->size < 2048u) {
        return -EINVAL;
    }
    struct ext2_mount* host = NULL;
    if (image_file->backend == FS_BACKEND_EXT2) {
        host = ext2_find_mount_by_path(image_file->path, NULL);
    }
    if (image_file->backend == FS_BACKEND_EXT2 && (host == NULL || host->ops == &g_ext2_file_ops)) {
        return -ENOTSUP;
    }

    struct ext2_mount mounted;
    struct ext2_file_storage_ctx file_storage;
    memset(&file_storage, 0, sizeof(file_storage));
    file_storage.backing = *image_file;
    file_storage.host = host;

    int r = ext2_build_mount(&mounted, mount_path, &g_ext2_file_ops, &file_storage, image_file->size, read_only);
    if (r != 0) {
        return r;
    }
    mounted.file_storage = file_storage;
    mounted.storage_ctx = &mounted.file_storage;

    struct ext2_mount* slot = ext2_find_mount_by_exact_path(mount_path);
    if (slot == NULL) {
        slot = ext2_find_free_mount_slot();
    }
    if (slot == NULL) {
        release_mount_cache(&mounted);
        return -ENOMEM;
    }

    ext2_destroy_mount(slot);
    *slot = mounted;
    g_ext2_current = slot;
    return 0;
}

int ext2_mount_file(const struct fs_entry* image_file, bool read_only) {
    return ext2_mount_file_at("/usr", image_file, read_only);
}

int ext2_sync_all(void) {
    int first_error = 0;

    for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
        if (!g_ext2_mounts[i].mounted) {
            continue;
        }
        struct ext2_mount* saved = g_ext2_current;
        g_ext2_current = &g_ext2_mounts[i];
        int r = ext2_sync_current(false);
        g_ext2_current = saved;
        if (r != 0 && first_error == 0) {
            first_error = r;
        }
    }

    return first_error;
}

int ext2_shutdown_all(void) {
    int first_error = 0;

    for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
        if (!g_ext2_mounts[i].mounted) {
            continue;
        }
        struct ext2_mount* saved = g_ext2_current;
        g_ext2_current = &g_ext2_mounts[i];
        int r = ext2_sync_current(true);
        g_ext2_current = saved;
        if (r != 0 && first_error == 0) {
            first_error = r;
        }
        ext2_destroy_mount(&g_ext2_mounts[i]);
    }

    return first_error;
}

bool ext2_is_mounted(void) {
    for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
        if (g_ext2_mounts[i].mounted) {
            return true;
        }
    }
    return false;
}

bool ext2_is_mounted_at(const char* mount_path) {
    return ext2_find_mount_by_exact_path(mount_path) != NULL;
}

bool ext2_is_read_only(void) {
    return !g_ext2_current->mounted || g_ext2.read_only;
}

bool ext2_is_read_only_path(const char* path) {
    struct ext2_mount* mount = ext2_find_mount_by_path(path, NULL);
    return mount == NULL || mount->read_only;
}

bool ext2_owns_path(const char* path) {
    return ext2_find_mount_by_path(path, NULL) != NULL;
}

static int ext2_push_mount_for_path(const char* path, struct ext2_mount** saved_out) {
    struct ext2_mount* mount = ext2_find_mount_by_path(path, NULL);
    if (mount == NULL || saved_out == NULL) {
        return (saved_out == NULL) ? -EINVAL : -ENOENT;
    }
    *saved_out = g_ext2_current;
    g_ext2_current = mount;
    return 0;
}

static int ext2_push_mount_for_entry(const struct fs_entry* entry, struct ext2_mount** saved_out) {
    if (entry == NULL) {
        return -EINVAL;
    }
    return ext2_push_mount_for_path(entry->path, saved_out);
}

static void ext2_pop_mount(struct ext2_mount* saved) {
    if (saved != NULL) {
        g_ext2_current = saved;
    }
}

int ext2_lookup(const char* path, struct fs_entry* out) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    const char* internal = NULL;
    if (!g_ext2.mounted || !ext2_internal_path(path, &internal)) {
        ext2_pop_mount(saved);
        return -ENOENT;
    }

    uint32_t inode_num = EXT2_ROOT_INO;
    if (strcmp(internal, "/") == 0) {
        int r = fill_entry(path, inode_num, out);
        ext2_pop_mount(saved);
        return r;
    }

    size_t i = 1;
    while (internal[i] != '\0') {
        char component[EXT2_NAME_LEN + 1u];
        size_t len = 0;
        while (internal[i] != '\0' && internal[i] != '/' && len + 1 < sizeof(component)) {
            component[len++] = internal[i++];
        }
        component[len] = '\0';

        while (internal[i] != '\0' && internal[i] != '/') {
            ++i;
        }
        while (internal[i] == '/') {
            ++i;
        }

        if (len == 0) {
            continue;
        }

        int lr = find_child_inode(inode_num, component, &inode_num, NULL);
        if (lr != 0) {
            ext2_pop_mount(saved);
            return lr;
        }
    }

    int r = fill_entry(path, inode_num, out);
    ext2_pop_mount(saved);
    return r;
}

int ext2_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count) {
    if (entry == NULL || buf == NULL || entry->backend != FS_BACKEND_EXT2) {
        return -EINVAL;
    }
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_entry(entry, &saved);
    if (sr != 0) {
        return sr;
    }

    struct ext2_inode inode;
    int ir = read_inode(entry->inode, &inode);
    if (ir != 0) {
        ext2_pop_mount(saved);
        return ir;
    }

    size_t file_size = (size_t)inode_file_size(&inode);
    int r = read_inode_bytes(&inode, file_size, offset, buf, count);
    ext2_pop_mount(saved);
    return r;
}

int ext2_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count) {
    if (entry == NULL || (buf == NULL && count != 0) || entry->backend != FS_BACKEND_EXT2) {
        return -EINVAL;
    }
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_entry(entry, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only || entry->read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }
    if (count == 0) {
        ext2_pop_mount(saved);
        return 0;
    }
    if (offset + count < offset) {
        ext2_pop_mount(saved);
        return -EINVAL;
    }

    struct ext2_inode inode;
    int ir = read_inode(entry->inode, &inode);
    if (ir != 0) {
        ext2_pop_mount(saved);
        return ir;
    }
    if ((inode.i_mode & FS_S_IFMT) != FS_S_IFREG) {
        ext2_pop_mount(saved);
        return -EINVAL;
    }

    size_t file_size = (size_t)inode_file_size(&inode);
    if (offset > file_size) {
        int zr = zero_inode_span(&inode, file_size, offset - file_size);
        if (zr < 0) {
            ext2_pop_mount(saved);
            return zr;
        }
    }

    int wr = write_inode_span(&inode, offset, buf, count);
    if (wr < 0) {
        ext2_pop_mount(saved);
        return wr;
    }

    size_t end = offset + (size_t)wr;
    if (end > file_size) {
        set_inode_file_size(&inode, end);
        entry->size = end;
    }

    int iw = write_inode(entry->inode, &inode);
    if (iw != 0) {
        ext2_pop_mount(saved);
        return iw;
    }
    int r = finish_mutation(wr);
    ext2_pop_mount(saved);
    return r;
}

int ext2_truncate(struct fs_entry* entry, size_t size) {
    if (entry == NULL || entry->backend != FS_BACKEND_EXT2) {
        return -EINVAL;
    }
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_entry(entry, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only || entry->read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    struct ext2_inode inode;
    int ir = read_inode(entry->inode, &inode);
    if (ir != 0) {
        ext2_pop_mount(saved);
        return ir;
    }
    if ((inode.i_mode & FS_S_IFMT) != FS_S_IFREG) {
        ext2_pop_mount(saved);
        return -EINVAL;
    }

    size_t old_size = (size_t)inode_file_size(&inode);
    if (size > old_size) {
        int zr = zero_inode_span(&inode, old_size, size - old_size);
        if (zr < 0) {
            ext2_pop_mount(saved);
            return zr;
        }
    } else if (size < old_size) {
        int fr = free_inode_blocks_from(&inode, old_size, size);
        if (fr != 0) {
            ext2_pop_mount(saved);
            return fr;
        }
    }

    set_inode_file_size(&inode, size);
    int iw = write_inode(entry->inode, &inode);
    if (iw != 0) {
        ext2_pop_mount(saved);
        return iw;
    }
    entry->size = size;
    int r = finish_mutation(0);
    ext2_pop_mount(saved);
    return r;
}

static int free_inode_contents(uint32_t inode_num, struct ext2_inode* inode) {
    if (inode == NULL) {
        return -EINVAL;
    }

    size_t old_size = (size_t)inode_file_size(inode);
    bool fast_symlink = (inode->i_mode & FS_S_IFMT) == FS_S_IFLNK && old_size <= sizeof(inode->i_block);
    if (!fast_symlink) {
        int fr = free_inode_blocks_from(inode, old_size, 0);
        if (fr != 0) {
            return fr;
        }
    }
    set_inode_file_size(inode, 0);
    inode->i_links_count = 0;
    inode->i_dtime = 1;
    int wr = write_inode(inode_num, inode);
    if (wr != 0) {
        return wr;
    }
    return free_inode_bitmap(inode_num, inode->i_mode);
}

static int create_inode_with_mode(uint32_t mode, uint16_t uid, uint16_t gid, uint16_t links, uint32_t rdev, uint32_t* inode_out,
                                  struct ext2_inode* inode_out_data) {
    uint32_t inode_num = 0;
    int ar = alloc_inode(0, mode, &inode_num);
    if (ar != 0) {
        return ar;
    }

    struct ext2_inode inode;
    memset(&inode, 0, sizeof(inode));
    inode.i_mode = (uint16_t)mode;
    inode.i_uid = uid;
    inode.i_gid = gid;
    inode.i_links_count = links;
    if ((mode & FS_S_IFMT) == FS_S_IFCHR || (mode & FS_S_IFMT) == FS_S_IFBLK || (mode & FS_S_IFMT) == FS_S_IFIFO ||
        (mode & FS_S_IFMT) == FS_S_IFSOCK) {
        inode.i_block[0] = rdev;
    }

    int wr = write_inode(inode_num, &inode);
    if (wr != 0) {
        (void)free_inode_bitmap(inode_num, mode);
        return wr;
    }
    if (inode_out != NULL) {
        *inode_out = inode_num;
    }
    if (inode_out_data != NULL) {
        *inode_out_data = inode;
    }
    return 0;
}

int ext2_create(const char* path, uint32_t mode, struct fs_entry* out) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(path, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    if (find_child_inode(parent_ino, name, NULL, NULL) == 0) {
        ext2_pop_mount(saved);
        return -EEXIST;
    }

    uint32_t file_mode = (mode & FS_S_IFMT) == 0u ? (FS_S_IFREG | (mode & 07777u)) : mode;
    uint32_t inode_num = 0;
    int cr = create_inode_with_mode(file_mode, 0, 0, 1, 0, &inode_num, NULL);
    if (cr != 0) {
        ext2_pop_mount(saved);
        return cr;
    }
    int ar = add_dirent(parent_ino, name, inode_num, ext2_mode_to_file_type(file_mode));
    if (ar != 0) {
        struct ext2_inode inode;
        if (read_inode(inode_num, &inode) == 0) {
            (void)free_inode_contents(inode_num, &inode);
        }
        ext2_pop_mount(saved);
        return ar;
    }

    int r = finish_mutation(fill_entry(path, inode_num, out));
    ext2_pop_mount(saved);
    return r;
}

int ext2_mknod(const char* path, uint32_t mode, uint32_t rdev, struct fs_entry* out) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    uint32_t type = mode & FS_S_IFMT;
    if (type != FS_S_IFREG && type != FS_S_IFCHR && type != FS_S_IFBLK && type != FS_S_IFIFO && type != FS_S_IFSOCK) {
        ext2_pop_mount(saved);
        return -EINVAL;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(path, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    if (find_child_inode(parent_ino, name, NULL, NULL) == 0) {
        ext2_pop_mount(saved);
        return -EEXIST;
    }

    uint32_t inode_num = 0;
    int cr = create_inode_with_mode(mode, 0, 0, 1, rdev, &inode_num, NULL);
    if (cr != 0) {
        ext2_pop_mount(saved);
        return cr;
    }
    int ar = add_dirent(parent_ino, name, inode_num, ext2_mode_to_file_type(mode));
    if (ar != 0) {
        struct ext2_inode inode;
        if (read_inode(inode_num, &inode) == 0) {
            (void)free_inode_contents(inode_num, &inode);
        }
        ext2_pop_mount(saved);
        return ar;
    }

    int r = finish_mutation(fill_entry(path, inode_num, out));
    ext2_pop_mount(saved);
    return r;
}

int ext2_mkdir(const char* path, uint32_t mode, struct fs_entry* out) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(path, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    if (find_child_inode(parent_ino, name, NULL, NULL) == 0) {
        ext2_pop_mount(saved);
        return -EEXIST;
    }

    uint32_t inode_num = 0;
    struct ext2_inode inode;
    uint32_t dir_mode = FS_S_IFDIR | (mode & 07777u);
    int cr = create_inode_with_mode(dir_mode, 0, 0, 2, 0, &inode_num, &inode);
    if (cr != 0) {
        ext2_pop_mount(saved);
        return cr;
    }

    int wr = write_dirent(&inode, 0, inode_num, ext2_dir_rec_len(1), ".", EXT2_FT_DIR);
    if (wr == 0) {
        wr = write_dirent(&inode, ext2_dir_rec_len(1), parent_ino,
                          (uint16_t)(g_ext2.block_size - ext2_dir_rec_len(1)), "..", EXT2_FT_DIR);
    }
    if (wr == 0) {
        set_inode_file_size(&inode, g_ext2.block_size);
        wr = write_inode(inode_num, &inode);
    }
    if (wr != 0) {
        (void)free_inode_contents(inode_num, &inode);
        ext2_pop_mount(saved);
        return wr;
    }

    int ar = add_dirent(parent_ino, name, inode_num, EXT2_FT_DIR);
    if (ar != 0) {
        (void)free_inode_contents(inode_num, &inode);
        ext2_pop_mount(saved);
        return ar;
    }

    struct ext2_inode parent;
    if (read_inode(parent_ino, &parent) == 0) {
        parent.i_links_count++;
        (void)write_inode(parent_ino, &parent);
    }

    int r = finish_mutation(fill_entry(path, inode_num, out));
    ext2_pop_mount(saved);
    return r;
}

int ext2_symlink(const char* target, const char* linkpath, struct fs_entry* out) {
    if (target == NULL) {
        return -EINVAL;
    }
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(linkpath, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(linkpath, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    if (find_child_inode(parent_ino, name, NULL, NULL) == 0) {
        ext2_pop_mount(saved);
        return -EEXIST;
    }

    uint32_t inode_num = 0;
    struct ext2_inode inode;
    int cr = create_inode_with_mode(FS_S_IFLNK | 0777u, 0, 0, 1, 0, &inode_num, &inode);
    if (cr != 0) {
        ext2_pop_mount(saved);
        return cr;
    }

    size_t target_len = strlen(target);
    if (target_len <= sizeof(inode.i_block)) {
        memcpy(inode.i_block, target, target_len);
        set_inode_file_size(&inode, target_len);
    } else {
        int wr = write_inode_span(&inode, 0, target, target_len);
        if (wr < (int)target_len) {
            (void)free_inode_contents(inode_num, &inode);
            ext2_pop_mount(saved);
            return wr < 0 ? wr : -ENOSPC;
        }
        set_inode_file_size(&inode, target_len);
    }

    int wr = write_inode(inode_num, &inode);
    if (wr != 0) {
        (void)free_inode_contents(inode_num, &inode);
        ext2_pop_mount(saved);
        return wr;
    }
    int ar = add_dirent(parent_ino, name, inode_num, EXT2_FT_SYMLINK);
    if (ar != 0) {
        (void)free_inode_contents(inode_num, &inode);
        ext2_pop_mount(saved);
        return ar;
    }

    int r = finish_mutation(fill_entry(linkpath, inode_num, out));
    ext2_pop_mount(saved);
    return r;
}

int ext2_link(const char* existing, const char* newpath) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(existing, &saved);
    if (sr != 0) {
        return sr;
    }
    if (ext2_find_mount_by_path(newpath, NULL) != g_ext2_current) {
        ext2_pop_mount(saved);
        return -EXDEV;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    uint32_t old_ino = 0;
    int lr = lookup_inode_number(existing, &old_ino);
    if (lr != 0) {
        ext2_pop_mount(saved);
        return lr;
    }
    struct ext2_inode old_inode;
    lr = read_inode(old_ino, &old_inode);
    if (lr != 0) {
        ext2_pop_mount(saved);
        return lr;
    }
    if ((old_inode.i_mode & FS_S_IFMT) == FS_S_IFDIR) {
        ext2_pop_mount(saved);
        return -EISDIR;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(newpath, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    int ar = add_dirent(parent_ino, name, old_ino, ext2_mode_to_file_type(old_inode.i_mode));
    if (ar != 0) {
        ext2_pop_mount(saved);
        return ar;
    }
    old_inode.i_links_count++;
    int r = finish_mutation(write_inode(old_ino, &old_inode));
    ext2_pop_mount(saved);
    return r;
}

int ext2_unlink(const char* path) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(path, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }

    uint32_t child_ino = 0;
    int rr = remove_dirent(parent_ino, name, &child_ino, NULL);
    if (rr != 0) {
        ext2_pop_mount(saved);
        return rr;
    }

    struct ext2_inode child;
    rr = read_inode(child_ino, &child);
    if (rr != 0) {
        ext2_pop_mount(saved);
        return rr;
    }
    if ((child.i_mode & FS_S_IFMT) == FS_S_IFDIR) {
        (void)add_dirent(parent_ino, name, child_ino, EXT2_FT_DIR);
        ext2_pop_mount(saved);
        return -EISDIR;
    }
    if (child.i_links_count > 0u) {
        child.i_links_count--;
    }
    if (child.i_links_count == 0u) {
        int r = finish_mutation(free_inode_contents(child_ino, &child));
        ext2_pop_mount(saved);
        return r;
    }
    int r = finish_mutation(write_inode(child_ino, &child));
    ext2_pop_mount(saved);
    return r;
}

int ext2_rmdir(const char* path) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    uint32_t dir_ino = 0;
    int lr = lookup_inode_number(path, &dir_ino);
    if (lr != 0) {
        ext2_pop_mount(saved);
        return lr;
    }
    if (dir_ino == EXT2_ROOT_INO) {
        ext2_pop_mount(saved);
        return -EINVAL;
    }
    struct ext2_inode dir_inode;
    lr = read_inode(dir_ino, &dir_inode);
    if (lr != 0) {
        ext2_pop_mount(saved);
        return lr;
    }
    if ((dir_inode.i_mode & FS_S_IFMT) != FS_S_IFDIR) {
        ext2_pop_mount(saved);
        return -ENOTDIR;
    }
    if (!dir_is_empty(dir_ino)) {
        ext2_pop_mount(saved);
        return -ENOTEMPTY;
    }

    char name[EXT2_NAME_LEN + 1u];
    uint32_t parent_ino = 0;
    int pr = lookup_parent_inode(path, &parent_ino, name, sizeof(name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    uint32_t removed = 0;
    int rr = remove_dirent(parent_ino, name, &removed, NULL);
    if (rr != 0) {
        ext2_pop_mount(saved);
        return rr;
    }

    struct ext2_inode parent;
    if (read_inode(parent_ino, &parent) == 0 && parent.i_links_count > 0u) {
        parent.i_links_count--;
        (void)write_inode(parent_ino, &parent);
    }
    int r = finish_mutation(free_inode_contents(dir_ino, &dir_inode));
    ext2_pop_mount(saved);
    return r;
}

int ext2_chmod(const char* path, uint32_t mode) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    uint32_t inode_num = 0;
    int r = lookup_inode_number(path, &inode_num);
    if (r != 0) {
        ext2_pop_mount(saved);
        return r;
    }
    struct ext2_inode inode;
    r = read_inode(inode_num, &inode);
    if (r != 0) {
        ext2_pop_mount(saved);
        return r;
    }
    inode.i_mode = (uint16_t)((inode.i_mode & FS_S_IFMT) | (mode & 07777u));
    r = finish_mutation(write_inode(inode_num, &inode));
    ext2_pop_mount(saved);
    return r;
}

int ext2_chown(const char* path, uint32_t uid, uint32_t gid) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(path, &saved);
    if (sr != 0) {
        return sr;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    uint32_t inode_num = 0;
    int r = lookup_inode_number(path, &inode_num);
    if (r != 0) {
        ext2_pop_mount(saved);
        return r;
    }
    struct ext2_inode inode;
    r = read_inode(inode_num, &inode);
    if (r != 0) {
        ext2_pop_mount(saved);
        return r;
    }
    if (uid != UINT32_MAX) {
        inode.i_uid = (uint16_t)uid;
    }
    if (gid != UINT32_MAX) {
        inode.i_gid = (uint16_t)gid;
    }
    r = finish_mutation(write_inode(inode_num, &inode));
    ext2_pop_mount(saved);
    return r;
}

int ext2_rename(const char* oldpath, const char* newpath) {
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_path(oldpath, &saved);
    if (sr != 0) {
        return sr;
    }
    if (ext2_find_mount_by_path(newpath, NULL) != g_ext2_current) {
        ext2_pop_mount(saved);
        return -EXDEV;
    }
    if (g_ext2.read_only) {
        ext2_pop_mount(saved);
        return -EROFS;
    }

    char old_name[EXT2_NAME_LEN + 1u];
    uint32_t old_parent = 0;
    int pr = lookup_parent_inode(oldpath, &old_parent, old_name, sizeof(old_name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    uint32_t old_ino = 0;
    uint8_t old_type = EXT2_FT_UNKNOWN;
    int fr = find_child_inode(old_parent, old_name, &old_ino, &old_type);
    if (fr != 0) {
        ext2_pop_mount(saved);
        return fr;
    }

    char new_name[EXT2_NAME_LEN + 1u];
    uint32_t new_parent = 0;
    pr = lookup_parent_inode(newpath, &new_parent, new_name, sizeof(new_name));
    if (pr != 0) {
        ext2_pop_mount(saved);
        return pr;
    }
    if (old_parent == new_parent && strcmp(old_name, new_name) == 0) {
        ext2_pop_mount(saved);
        return 0;
    }

    uint32_t existing = 0;
    if (find_child_inode(new_parent, new_name, &existing, NULL) == 0) {
        struct ext2_inode existing_inode;
        int er = read_inode(existing, &existing_inode);
        if (er != 0) {
            ext2_pop_mount(saved);
            return er;
        }
        if ((existing_inode.i_mode & FS_S_IFMT) == FS_S_IFDIR) {
            er = ext2_rmdir(newpath);
        } else {
            er = ext2_unlink(newpath);
        }
        if (er != 0) {
            ext2_pop_mount(saved);
            return er;
        }
    }

    int ar = add_dirent(new_parent, new_name, old_ino, old_type);
    if (ar != 0) {
        ext2_pop_mount(saved);
        return ar;
    }
    uint32_t removed = 0;
    ar = remove_dirent(old_parent, old_name, &removed, NULL);
    if (ar != 0) {
        (void)remove_dirent(new_parent, new_name, NULL, NULL);
        ext2_pop_mount(saved);
        return ar;
    }

    struct ext2_inode moved;
    if (old_parent != new_parent && old_type == EXT2_FT_DIR && read_inode(old_ino, &moved) == 0) {
        (void)remove_dirent(old_ino, "..", NULL, NULL);
        (void)add_dirent(old_ino, "..", new_parent, EXT2_FT_DIR);

        struct ext2_inode oldp;
        if (read_inode(old_parent, &oldp) == 0 && oldp.i_links_count > 0u) {
            oldp.i_links_count--;
            (void)write_inode(old_parent, &oldp);
        }
        struct ext2_inode newp;
        if (read_inode(new_parent, &newp) == 0) {
            newp.i_links_count++;
            (void)write_inode(new_parent, &newp);
        }
    }

    int r = finish_mutation(0);
    ext2_pop_mount(saved);
    return r;
}

int ext2_readlink(const struct fs_entry* entry, char* out, size_t bufsz) {
    if (entry == NULL || out == NULL || entry->backend != FS_BACKEND_EXT2) {
        return -EINVAL;
    }
    struct ext2_mount* saved = NULL;
    int sr = ext2_push_mount_for_entry(entry, &saved);
    if (sr != 0) {
        return sr;
    }

    struct ext2_inode inode;
    int ir = read_inode(entry->inode, &inode);
    if (ir != 0) {
        ext2_pop_mount(saved);
        return ir;
    }
    if ((inode.i_mode & FS_S_IFMT) != FS_S_IFLNK) {
        ext2_pop_mount(saved);
        return -EINVAL;
    }

    size_t size = (size_t)inode_file_size(&inode);
    if (size > bufsz) {
        size = bufsz;
    }

    if (inode_file_size(&inode) <= sizeof(inode.i_block)) {
        memcpy(out, inode.i_block, size);
        ext2_pop_mount(saved);
        return (int)size;
    }

    int r = read_inode_bytes(&inode, (size_t)inode_file_size(&inode), 0, out, size);
    ext2_pop_mount(saved);
    return r;
}

static bool ext2_children_contains(char names[][FS_MAX_NAME], size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return true;
        }
    }
    return false;
}

static size_t ext2_root_mount_name(const struct ext2_mount* mount, char* out, size_t out_len) {
    if (mount == NULL || !mount->mounted || out == NULL || out_len == 0 || mount->mount_path_len <= 1u) {
        return 0;
    }

    size_t len = 0;
    const char* src = mount->mount_path + 1;
    while (src[len] != '\0' && src[len] != '/' && len + 1u < out_len) {
        out[len] = src[len];
        ++len;
    }
    if (len == 0 || src[len] != '\0') {
        return 0;
    }
    out[len] = '\0';
    return len;
}

bool ext2_path_has_child(const char* dir) {
    if (strcmp(dir, "/") == 0) {
        for (size_t i = 0; i < EXT2_MAX_MOUNTS; ++i) {
            if (g_ext2_mounts[i].mounted && g_ext2_mounts[i].mount_path_len > 1u) {
                return true;
            }
        }
        return false;
    }

    struct ext2_mount* saved = NULL;
    if (ext2_push_mount_for_path(dir, &saved) != 0) {
        return false;
    }

    struct fs_entry entry;
    int lr = ext2_lookup(dir, &entry);
    if (lr != 0 || (entry.mode & FS_S_IFMT) != FS_S_IFDIR) {
        ext2_pop_mount(saved);
        return false;
    }

    struct ext2_inode inode;
    if (read_inode(entry.inode, &inode) != 0) {
        ext2_pop_mount(saved);
        return false;
    }

    size_t dir_size = (size_t)inode_file_size(&inode);
    size_t offset = 0;
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head) || head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            ext2_pop_mount(saved);
            return false;
        }

        if (head.inode != 0 && head.name_len != 0 && head.name_len < FS_MAX_NAME) {
            char name[FS_MAX_NAME];
            rr = read_inode_bytes(&inode, dir_size, offset + sizeof(head), name, head.name_len);
            if (rr < 0) {
                ext2_pop_mount(saved);
                return false;
            }
            name[head.name_len] = '\0';
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                ext2_pop_mount(saved);
                return true;
            }
        }

        offset += head.rec_len;
    }

    ext2_pop_mount(saved);
    return false;
}

size_t ext2_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children) {
    if (max_children == 0) {
        return 0;
    }

    if (strcmp(dir, "/") == 0) {
        size_t count = 0;
        for (size_t i = 0; i < EXT2_MAX_MOUNTS && count < max_children; ++i) {
            char mount_name[FS_MAX_NAME];
            if (ext2_root_mount_name(&g_ext2_mounts[i], mount_name, sizeof(mount_name)) == 0 ||
                ext2_children_contains(names, count, mount_name)) {
                continue;
            }
            strcpy(names[count], mount_name);
            types[count] = FS_DT_DIR;
            ++count;
        }
        return count;
    }

    struct ext2_mount* saved = NULL;
    if (ext2_push_mount_for_path(dir, &saved) != 0) {
        return 0;
    }

    struct fs_entry entry;
    int lr = ext2_lookup(dir, &entry);
    if (lr != 0 || (entry.mode & FS_S_IFMT) != FS_S_IFDIR) {
        ext2_pop_mount(saved);
        return 0;
    }

    struct ext2_inode inode;
    if (read_inode(entry.inode, &inode) != 0) {
        ext2_pop_mount(saved);
        return 0;
    }

    size_t count = 0;
    size_t dir_size = (size_t)inode_file_size(&inode);
    size_t offset = 0;
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size && count < max_children) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head) || head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            break;
        }

        if (head.inode != 0 && head.name_len != 0 && head.name_len < FS_MAX_NAME && head.name_len <= head.rec_len - sizeof(head)) {
            rr = read_inode_bytes(&inode, dir_size, offset + sizeof(head), names[count], head.name_len);
            if (rr < 0) {
                break;
            }
            names[count][head.name_len] = '\0';

            if (strcmp(names[count], ".") != 0 && strcmp(names[count], "..") != 0) {
                struct ext2_inode child_inode;
                if (read_inode(head.inode, &child_inode) == 0) {
                    types[count] = ext2_ft_to_dtype(head.file_type, child_inode.i_mode);
                } else {
                    types[count] = FS_DT_UNKNOWN;
                }
                ++count;
            }
        }

        offset += head.rec_len;
    }

    ext2_pop_mount(saved);
    return count;
}
