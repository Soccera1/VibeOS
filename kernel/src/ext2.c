#include "ext2.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "kmalloc.h"
#include "string.h"

#define EINVAL 22
#define ENOENT 2
#define ENOMEM 12

#define EXT2_SUPER_MAGIC 0xEF53u
#define EXT2_ROOT_INO 2u
#define EXT2_NDIR_BLOCKS 12u
#define EXT2_IND_BLOCK 12u
#define EXT2_DIND_BLOCK 13u
#define EXT2_TIND_BLOCK 14u

#define EXT2_FT_UNKNOWN 0u
#define EXT2_FT_REG_FILE 1u
#define EXT2_FT_DIR 2u
#define EXT2_FT_CHRDEV 3u
#define EXT2_FT_BLKDEV 4u
#define EXT2_FT_FIFO 5u
#define EXT2_FT_SOCK 6u
#define EXT2_FT_SYMLINK 7u

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

struct ext2_mount {
    bool mounted;
    const uint8_t* image;
    size_t size;
    uint32_t block_size;
    uint32_t blocks_count;
    uint32_t blocks_per_group;
    uint32_t inodes_per_group;
    uint32_t inode_size;
    uint32_t group_count;
};

static struct ext2_mount g_ext2;

static int min_int(int a, int b) {
    return (a < b) ? a : b;
}

static uint64_t inode_file_size(const struct ext2_inode* inode) {
    uint64_t size = inode->i_size;
    if ((inode->i_mode & FS_S_IFMT) == FS_S_IFREG) {
        size |= ((uint64_t)inode->i_dir_acl << 32);
    }
    return size;
}

static bool ext2_internal_path(const char* path, const char** internal_out) {
    if (path == NULL) {
        return false;
    }
    if (strcmp(path, "/usr") == 0) {
        *internal_out = "/";
        return true;
    }
    if (strncmp(path, "/usr/", 5) == 0) {
        *internal_out = path + 4;
        return true;
    }
    return false;
}

static const uint8_t* block_ptr(uint32_t block_num) {
    if (block_num == 0) {
        return NULL;
    }
    uint64_t offset = (uint64_t)block_num * g_ext2.block_size;
    if (offset + g_ext2.block_size > g_ext2.size) {
        return NULL;
    }
    return g_ext2.image + offset;
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

    memcpy(out, g_ext2.image + offset, sizeof(*out));
    return 0;
}

static int read_inode(uint32_t inode_num, struct ext2_inode* out) {
    if (!g_ext2.mounted || out == NULL || inode_num == 0) {
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

    memset(out, 0, sizeof(*out));
    memcpy(out, g_ext2.image + inode_off, min_int((int)sizeof(*out), (int)g_ext2.inode_size));
    return 0;
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

static uint8_t ext2_ft_to_dtype(uint8_t file_type, uint32_t mode) {
    switch (file_type) {
        case EXT2_FT_REG_FILE:
            return FS_DT_REG;
        case EXT2_FT_DIR:
            return FS_DT_DIR;
        case EXT2_FT_CHRDEV:
            return FS_DT_CHR;
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

        if (head.inode != 0 && head.name_len != 0 && head.name_len <= head.rec_len - sizeof(head) && head.name_len < FS_MAX_NAME) {
            char entry_name[FS_MAX_NAME];
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
    }

    return 0;
}

void ext2_mount_image(const uint8_t* image, size_t size) {
    memset(&g_ext2, 0, sizeof(g_ext2));

    if (image == NULL || size < 2048u) {
        return;
    }

    uint8_t* copy = kmalloc(size);
    if (copy != NULL) {
        memcpy(copy, image, size);
        image = copy;
    }

    const struct ext2_superblock* sb = (const struct ext2_superblock*)(image + 1024u);
    if (sb->s_magic != EXT2_SUPER_MAGIC) {
        return;
    }

    g_ext2.image = image;
    g_ext2.size = size;
    g_ext2.block_size = 1024u << sb->s_log_block_size;
    g_ext2.blocks_count = sb->s_blocks_count;
    g_ext2.blocks_per_group = sb->s_blocks_per_group;
    g_ext2.inodes_per_group = sb->s_inodes_per_group;
    g_ext2.inode_size = (sb->s_inode_size >= sizeof(struct ext2_inode)) ? sb->s_inode_size : sizeof(struct ext2_inode);
    g_ext2.group_count = (g_ext2.blocks_count + g_ext2.blocks_per_group - 1u) / g_ext2.blocks_per_group;
    g_ext2.mounted = (g_ext2.block_size >= 1024u && g_ext2.group_count != 0u && g_ext2.inodes_per_group != 0u);
}

bool ext2_is_mounted(void) {
    return g_ext2.mounted;
}

bool ext2_owns_path(const char* path) {
    const char* ignored = NULL;
    return g_ext2.mounted && ext2_internal_path(path, &ignored);
}

int ext2_lookup(const char* path, struct fs_entry* out) {
    const char* internal = NULL;
    if (!g_ext2.mounted || !ext2_internal_path(path, &internal)) {
        return -ENOENT;
    }

    uint32_t inode_num = EXT2_ROOT_INO;
    if (strcmp(internal, "/") == 0) {
        return fill_entry(path, inode_num, out);
    }

    size_t i = 1;
    while (internal[i] != '\0') {
        char component[FS_MAX_NAME];
        size_t len = 0;
        while (internal[i] != '\0' && internal[i] != '/' && len + 1 < sizeof(component)) {
            component[len++] = internal[i++];
        }
        component[len] = '\0';

        while (internal[i] == '/') {
            ++i;
        }

        if (len == 0) {
            continue;
        }

        int lr = find_child_inode(inode_num, component, &inode_num, NULL);
        if (lr != 0) {
            return lr;
        }
    }

    return fill_entry(path, inode_num, out);
}

int ext2_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count) {
    if (entry == NULL || buf == NULL || entry->backend != FS_BACKEND_EXT2) {
        return -EINVAL;
    }

    struct ext2_inode inode;
    int ir = read_inode(entry->inode, &inode);
    if (ir != 0) {
        return ir;
    }

    size_t file_size = (size_t)inode_file_size(&inode);
    return read_inode_bytes(&inode, file_size, offset, buf, count);
}

int ext2_readlink(const struct fs_entry* entry, char* out, size_t bufsz) {
    if (entry == NULL || out == NULL || entry->backend != FS_BACKEND_EXT2) {
        return -EINVAL;
    }

    struct ext2_inode inode;
    int ir = read_inode(entry->inode, &inode);
    if (ir != 0) {
        return ir;
    }
    if ((inode.i_mode & FS_S_IFMT) != FS_S_IFLNK) {
        return -EINVAL;
    }

    size_t size = (size_t)inode_file_size(&inode);
    if (size > bufsz) {
        size = bufsz;
    }

    if (inode_file_size(&inode) <= sizeof(inode.i_block)) {
        memcpy(out, inode.i_block, size);
        return (int)size;
    }

    return read_inode_bytes(&inode, (size_t)inode_file_size(&inode), 0, out, size);
}

bool ext2_path_has_child(const char* dir) {
    struct fs_entry entry;
    int lr = ext2_lookup(dir, &entry);
    if (lr != 0 || (entry.mode & FS_S_IFMT) != FS_S_IFDIR) {
        return false;
    }

    struct ext2_inode inode;
    if (read_inode(entry.inode, &inode) != 0) {
        return false;
    }

    size_t dir_size = (size_t)inode_file_size(&inode);
    size_t offset = 0;
    while (offset + sizeof(struct ext2_dirent_head) <= dir_size) {
        struct ext2_dirent_head head;
        int rr = read_inode_bytes(&inode, dir_size, offset, &head, sizeof(head));
        if (rr < (int)sizeof(head) || head.rec_len < sizeof(head) || offset + head.rec_len > dir_size) {
            return false;
        }

        if (head.inode != 0 && head.name_len != 0 && head.name_len < FS_MAX_NAME) {
            char name[FS_MAX_NAME];
            rr = read_inode_bytes(&inode, dir_size, offset + sizeof(head), name, head.name_len);
            if (rr < 0) {
                return false;
            }
            name[head.name_len] = '\0';
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                return true;
            }
        }

        offset += head.rec_len;
    }

    return false;
}

size_t ext2_collect_children(const char* dir, char names[][FS_MAX_NAME], uint8_t types[], size_t max_children) {
    if (max_children == 0) {
        return 0;
    }

    struct fs_entry entry;
    int lr = ext2_lookup(dir, &entry);
    if (lr != 0 || (entry.mode & FS_S_IFMT) != FS_S_IFDIR) {
        return 0;
    }

    struct ext2_inode inode;
    if (read_inode(entry.inode, &inode) != 0) {
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

    return count;
}
