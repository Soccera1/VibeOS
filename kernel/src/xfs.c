/* Read-only XFS v4/v5 data fork reader. No journal replay or metadata writes.
 * Disk layout: XFS Algorithms & Data Structures, and libxfs/xfs*_format.h.
 * Decode bytes explicitly: XFS metadata is big endian except CRC32c fields.
 */
#include "xfs.h"
#include "kmalloc.h"
#include "string.h"

#define EIO 5
#define ENOENT 2
#define ENOMEM 12
#define EBUSY 16
#define ENODEV 19
#define ENOTDIR 20
#define EINVAL 22
#define EROFS 30
#define ENAMETOOLONG 36
#define ENOTSUP 95
#define XFS_MOUNTS 4

struct xfs_mount {
    bool used, crc, ftype;
    char path[FS_MAX_PATH];
    const struct ext2_storage_ops* ops;
    void* ctx;
    size_t size;
    uint32_t blocksize, agblocks, agcount, dirsize;
    uint16_t inodesize;
    uint8_t aglog, inoplog;
    uint64_t blocks, root;
    uint8_t uuid[16];
    struct fs_entry file;
};
struct xfs_inode {
    uint8_t bytes[2048];
    uint64_t number, size, extents;
    size_t core, fork;
    uint16_t mode;
    uint8_t format;
};
static struct xfs_mount mounts[XFS_MOUNTS];

static uint16_t be16(const uint8_t* p) { return (uint16_t)p[0] << 8 | p[1]; }
static uint32_t be32(const uint8_t* p) { return (uint32_t)be16(p) << 16 | be16(p + 2); }
static uint64_t be64(const uint8_t* p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }
static bool crc_ok(const uint8_t* p, size_t size, size_t off) {
    uint32_t crc = ~0u;
    for (size_t i = 0; i < size; ++i) {
        crc ^= i >= off && i < off + 4 ? 0 : p[i];
        for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0x82f63b78u & (0u - (crc & 1u)));
    }
    uint32_t stored = (uint32_t)p[off] | (uint32_t)p[off+1] << 8 |
                      (uint32_t)p[off+2] << 16 | (uint32_t)p[off+3] << 24;
    return ~crc == stored;
}
static bool under(const char* path, const char* root) {
    size_t n = strlen(root);
    return path && strncmp(path, root, n) == 0 && (path[n] == 0 || path[n] == '/');
}
static struct xfs_mount* mount_for(const char* path) {
    for (size_t i = 0; i < XFS_MOUNTS; ++i)
        if (mounts[i].used && under(path, mounts[i].path)) return &mounts[i];
    return NULL;
}
bool xfs_owns_path(const char* path) { return mount_for(path) != NULL; }
bool xfs_is_mounted_at(const char* path) {
    struct xfs_mount* m = mount_for(path);
    return m && strcmp(path, m->path) == 0;
}
static int disk_read(struct xfs_mount* m, uint64_t off, void* buf, size_t len) {
    if (off > m->size || len > m->size - off) return -EIO;
    return m->ops->read(m->ctx, off, buf, len) == 0 ? 0 : -EIO;
}
/* Encoded filesystem block numbers contain an AG number and a rounded-up
 * AG-relative block number; they are not linear disk block numbers. */
static int block_offset(struct xfs_mount* m, uint64_t fsb, uint64_t* off) {
    uint64_t ag = fsb >> m->aglog;
    uint64_t block = fsb & ((1ull << m->aglog) - 1);
    if (ag >= m->agcount || block >= m->agblocks) return -EIO;
    uint64_t linear = ag * m->agblocks + block;
    if (linear >= m->blocks) return -EIO;
    *off = linear * m->blocksize;
    return 0;
}
static int inode_read(struct xfs_mount* m, uint64_t number, struct xfs_inode* ino) {
    uint64_t off;
    if (!number || block_offset(m, number >> m->inoplog, &off)) return -EIO;
    off += (number & ((1ull << m->inoplog) - 1)) * m->inodesize;
    if (disk_read(m, off, ino->bytes, m->inodesize)) return -EIO;
    const uint8_t* p = ino->bytes;
    if (be16(p) != 0x494e || p[4] != (m->crc ? 3 : 2)) return -EIO;
    if (m->crc && (!crc_ok(p, m->inodesize, 100) || be64(p+152) != number ||
                   memcmp(p+160, m->uuid, 16))) return -EIO;
    if (be16(p+90) & 1) return -ENOTSUP; /* realtime data device */
    ino->number = number;
    ino->mode = be16(p+2);
    ino->format = p[5];
    ino->size = be64(p+56);
    ino->core = m->crc ? 176 : 100;
    ino->fork = p[82] ? (size_t)p[82] * 8 : m->inodesize - ino->core;
    ino->extents = m->crc && (be64(p+120) & (1ull << 4)) ? be64(p+24) : be32(p+76);
    if (ino->fork > m->inodesize - ino->core || ino->size > INT64_MAX) return -EIO;
    if (ino->format == 1 && ino->size > ino->fork) return -EIO;
    if (ino->format == 2 && ino->extents > ino->fork / 16) return -EIO;
    if (ino->format < 1 || ino->format > 3) return -ENOTSUP;
    return 0;
}
/* Return one mapping; absent and unwritten extents read as zeroes. */
static int extent_find(struct xfs_mount* m, const struct xfs_inode* ino,
                       uint64_t logical, uint64_t* physical, bool* hole) {
    const uint8_t* data = ino->bytes + ino->core;
    uint8_t* block = NULL;
    size_t count = (size_t)ino->extents;
    int result = -EIO;
    *hole = true;
    if (ino->format == 3) {
        if (ino->fork < 4) return -EIO;
        unsigned level = be16(data), n = be16(data+2);
        size_t capacity = (ino->fork - 4) / 16;
        if (!level || level > 8 || !n || n > capacity) return -EIO;
        const uint8_t* keys = data+4;
        const uint8_t* ptrs = keys+capacity*8;
        block = kmalloc(m->blocksize);
        if (!block) return -ENOMEM;
        for (;;) {
            size_t index = 0;
            if (logical < be64(keys)) { result = 0; goto done; }
            for (size_t i = 1; i < n; ++i) {
                if (be64(keys+i*8) <= be64(keys+(i-1)*8)) goto done;
                if (be64(keys+i*8) <= logical) index = i;
            }
            uint64_t off;
            if (block_offset(m, be64(ptrs+index*8), &off) || disk_read(m, off, block, m->blocksize)) goto done;
            size_t header = m->crc ? 72 : 24;
            if (be32(block) != (m->crc ? 0x424d4133u : 0x424d4150u) || be16(block+4) != --level) goto done;
            if (m->crc && (!crc_ok(block, m->blocksize, 64) || be64(block+24) != off/512 ||
                           memcmp(block+40, m->uuid, 16) || be64(block+56) != ino->number)) goto done;
            n = be16(block+6);
            capacity = (m->blocksize-header)/16;
            if (!n || n > capacity) goto done;
            if (!level) { data = block+header; count = n; break; }
            keys = block+header;
            ptrs = keys+capacity*8;
        }
    } else if (ino->format != 2) return -ENOTSUP;
    uint64_t previous_end = 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t a = be64(data+i*16), b = be64(data+i*16+8);
        uint64_t start = (a >> 9) & ((1ull << 54)-1);
        uint64_t fsb = ((a & 511) << 43) | (b >> 21);
        uint64_t len = b & ((1u << 21)-1);
        if (!len || (i && start < previous_end)) goto done;
        previous_end = start+len;
        if (logical < start || logical >= start+len) continue;
        /* An extent cannot cross an allocation group boundary. */
        uint64_t agb = fsb & ((1ull << m->aglog)-1);
        if (agb >= m->agblocks || len > m->agblocks-agb || block_offset(m, fsb+len-1, physical)) goto done;
        if (block_offset(m, fsb+logical-start, physical)) goto done;
        *hole = (a >> 63) != 0;
        result = 0;
        goto done;
    }
    result = 0;
done:
    kfree(block);
    return result;
}
static int data_read(struct xfs_mount* m, const struct xfs_inode* ino,
                     uint64_t offset, void* buf, size_t count) {
    if (count > INT32_MAX) return -EINVAL;
    if (offset >= ino->size) return 0;
    if (count > ino->size-offset) count = ino->size-offset;
    if (ino->format == 1) {
        memcpy(buf, ino->bytes+ino->core+offset, count);
        return (int)count;
    }
    size_t done = 0;
    while (done < count) {
        uint64_t off = offset+done, physical;
        size_t within = off % m->blocksize;
        size_t n = m->blocksize-within;
        if (n > count-done) n = count-done;
        bool hole;
        int r = extent_find(m, ino, off/m->blocksize, &physical, &hole);
        if (r) return r;
        if (hole) memset((uint8_t*)buf+done, 0, n);
        else if (disk_read(m, physical+within, (uint8_t*)buf+done, n)) return -EIO;
        done += n;
    }
    return (int)done;
}

static bool valid_name(const uint8_t* name, size_t len) {
    for (size_t i = 0; i < len; ++i) if (!name[i] || name[i] == '/') return false;
    return len != 0;
}

typedef int (*dir_callback)(const uint8_t*, size_t, uint64_t, void*);
static int directory_walk(struct xfs_mount* m, const struct xfs_inode* ino, dir_callback cb, void* ctx) {
    if ((ino->mode & FS_S_IFMT) != FS_S_IFDIR) return -ENOTDIR;
    if (ino->format == 1) {
        const uint8_t* p = ino->bytes+ino->core;
        if (ino->size < 2) return -EIO;
        size_t width = p[1] ? 8 : 4, pos = 2+width;
        if (pos > ino->size) return -EIO;
        for (unsigned i = 0; i < p[0]; ++i) {
            if (pos+3 > ino->size) return -EIO;
            size_t len = p[pos], end = pos+3+len+m->ftype+width;
            if (!len || end > ino->size) return -EIO;
            if (!valid_name(p+pos+3, len) || (m->ftype && p[pos+3+len] > 8)) return -EIO;
            const uint8_t* num = p+end-width;
            int r = cb(p+pos+3, len, width == 8 ? be64(num) : be32(num), ctx);
            if (r) return r;
            pos = end;
        }
        return pos == ino->size ? 0 : -EIO;
    }
    if (!ino->size || ino->size % m->dirsize || ino->size > (1ull << 35)) return -EIO;
    uint8_t* block = kmalloc(m->dirsize);
    if (!block) return -ENOMEM;
    int result = 0;
    for (uint64_t off = 0; off < ino->size; off += m->dirsize) {
        uint64_t physical;
        bool hole;
        result = extent_find(m, ino, off/m->blocksize, &physical, &hole);
        if (result) break;
        if (hole) continue;
        if (data_read(m, ino, off, block, m->dirsize) != (int)m->dirsize) { result = -EIO; break; }
        uint32_t magic = be32(block);
        bool combined = magic == (m->crc ? 0x58444233u : 0x58443242u);
        size_t pos = m->crc ? 64 : 16, end = m->dirsize;
        if (!combined && magic != (m->crc ? 0x58444433u : 0x58443244u)) { result = -EIO; break; }
        if (m->crc && (!crc_ok(block, m->dirsize, 4) || be64(block+8) != physical/512 ||
                       memcmp(block+24, m->uuid, 16) || be64(block+40) != ino->number)) { result = -EIO; break; }
        if (combined) {
            size_t leaves = be32(block+end-8);
            if (leaves > (end-pos-8)/8) { result = -EIO; break; }
            end -= 8+leaves*8;
        }
        while (pos < end) {
            if (end-pos < 8) { result = -EIO; break; }
            size_t len;
            if (be16(block+pos) == 0xffff) {
                len = be16(block+pos+2);
                if (len < 8 || len % 8 || len > end-pos || be16(block+pos+len-2) != pos) { result = -EIO; break; }
            } else {
                if (end-pos < 9) { result = -EIO; break; }
                size_t namelen = block[pos+8];
                len = (9+namelen+m->ftype+2+7) & ~(size_t)7;
                if (!namelen || len > end-pos || be16(block+pos+len-2) != pos) { result = -EIO; break; }
                if (!valid_name(block+pos+9, namelen) || (m->ftype && block[pos+9+namelen] > 8)) { result = -EIO; break; }
                result = cb(block+pos+9, namelen, be64(block+pos), ctx);
                if (result) break;
            }
            pos += len;
        }
        if (result) break;
    }
    kfree(block);
    return result;
}
struct find_name { const char* name; size_t len; uint64_t number; };
static int find_entry(const uint8_t* name, size_t len, uint64_t number, void* ctx) {
    struct find_name* f = ctx;
    if (len == f->len && !memcmp(name, f->name, len)) { f->number = number; return 1; }
    return 0;
}
int xfs_lookup(const char* path, struct fs_entry* out) {
    if (!path) return -EINVAL;
    if (strlen(path) >= FS_MAX_PATH) return -ENAMETOOLONG;
    struct xfs_mount* m = mount_for(path);
    if (!m) return -ENOENT;
    struct xfs_inode ino;
    int r = inode_read(m, m->root, &ino);
    const char* p = path+strlen(m->path);
    while (!r && *p) {
        while (*p == '/') ++p;
        if (!*p) { if ((ino.mode & FS_S_IFMT) != FS_S_IFDIR) return -ENOTDIR; break; }
        const char* end = p;
        while (*end && *end != '/') ++end;
        struct find_name f = {p, (size_t)(end-p), 0};
        r = directory_walk(m, &ino, find_entry, &f);
        if (r != 1) return r < 0 ? r : -ENOENT;
        r = inode_read(m, f.number, &ino);
        p = end;
    }
    if (r) return r;
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    strcpy(out->path, path);
    out->size = ino.size;
    out->mode = ino.mode;
    out->uid = be32(ino.bytes+8);
    out->gid = be32(ino.bytes+12);
    out->inode = ino.number;
    out->backend = FS_BACKEND_XFS;
    out->read_only = true;
    return 0;
}
int xfs_read(const struct fs_entry* entry, size_t offset, void* buf, size_t count) {
    if (!entry || (!buf && count) || entry->backend != FS_BACKEND_XFS) return -EINVAL;
    struct xfs_mount* m = mount_for(entry->path);
    if (!m) return -ENOENT;
    struct xfs_inode ino;
    int r = inode_read(m, entry->inode, &ino);
    return r ? r : data_read(m, &ino, offset, buf, count);
}
int xfs_readlink(const struct fs_entry* entry, char* buf, size_t count) {
    if (!entry || !buf || entry->backend != FS_BACKEND_XFS || (entry->mode & FS_S_IFMT) != FS_S_IFLNK) return -EINVAL;
    struct xfs_mount* m = mount_for(entry->path);
    if (!m) return -ENOENT;
    struct xfs_inode ino;
    int r = inode_read(m, entry->inode, &ino);
    if (r) return r;
    if (ino.size > 1024) return -EIO;
    if (!m->crc || ino.format == 1) return data_read(m, &ino, 0, buf, count);
    uint8_t* block = kmalloc(m->blocksize);
    if (!block) return -ENOMEM;
    size_t done = 0, copied = 0;
    for (uint64_t logical = 0; done < ino.size; ++logical) {
        uint64_t off;
        bool hole;
        r = extent_find(m, &ino, logical, &off, &hole);
        if (r) break;
        if (hole || disk_read(m, off, block, m->blocksize) || be32(block) != 0x58534c4d ||
            !crc_ok(block, m->blocksize, 12) || be32(block+4) != done ||
            memcmp(block+16, m->uuid, 16) || be64(block+32) != ino.number || be64(block+40) != off/512) { r = -EIO; break; }
        size_t n = be32(block+8);
        if (!n || n > m->blocksize-56 || n > ino.size-done) { r = -EIO; break; }
        size_t take = n < count-copied ? n : count-copied;
        memcpy(buf+copied, block+56, take);
        copied += take;
        done += n;
    }
    kfree(block);
    return r ? r : (int)copied;
}
struct collect_ctx { struct xfs_mount* m; char (*names)[FS_MAX_NAME]; uint8_t* types; size_t count, max; };
static int collect_entry(const uint8_t* name, size_t len, uint64_t number, void* ctx) {
    struct collect_ctx* c = ctx;
    if ((len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.')) return 0;
    if (len >= FS_MAX_NAME) return 0; /* same namespace limit as ext2 */
    struct xfs_inode ino;
    int r = inode_read(c->m, number, &ino);
    if (r) return r;
    memcpy(c->names[c->count], name, len);
    c->names[c->count][len] = 0;
    c->types[c->count++] = fs_mode_to_dtype(ino.mode);
    return c->count == c->max ? 1 : 0;
}
size_t xfs_collect_children(const char* path, char names[][FS_MAX_NAME], uint8_t types[], size_t max) {
    if (!path || !max || !names || !types) return 0;
    struct collect_ctx c = {mount_for(path), names, types, 0, max};
    if (!strcmp(path, "/")) {
        for (size_t i = 0; i < XFS_MOUNTS && c.count < max; ++i) {
            if (!mounts[i].used) continue;
            strcpy(names[c.count], mounts[i].path+1);
            types[c.count++] = FS_DT_DIR;
        }
        return c.count;
    }
    struct fs_entry entry;
    struct xfs_inode ino;
    if (!c.m || xfs_lookup(path, &entry) || inode_read(c.m, entry.inode, &ino)) return 0;
    int r = directory_walk(c.m, &ino, collect_entry, &c);
    return r < 0 ? 0 : c.count;
}
static int memory_read(void* ctx, uint64_t off, void* buf, size_t len) {
    memcpy(buf, (const uint8_t*)ctx+off, len);
    return 0;
}
static int file_read(void* ctx, uint64_t off, void* buf, size_t len) {
    return fs_read(ctx, off, buf, len) == (int)len ? 0 : -EIO;
}
static const struct ext2_storage_ops memory_ops = {memory_read, NULL};
static const struct ext2_storage_ops file_ops = {file_read, NULL};
int xfs_mount_storage_at(const char* path, const struct ext2_storage_ops* ops, void* ctx, size_t size, bool read_only) {
#ifndef CONFIG_KERNEL_XFS
    (void)path; (void)ops; (void)ctx; (void)size; (void)read_only;
    return -ENODEV;
#endif
    if (!read_only) return -EROFS;
    /* Like the other boot backends, expose mounts immediately below root. */
    if (!path || path[0] != '/' || !path[1] || strlen(path) >= FS_MAX_NAME ||
        !strcmp(path, "/.") || !strcmp(path, "/..") || !ops || !ops->read) return -EINVAL;
    for (const char* p = path+1; *p; ++p) if (*p == '/') return -EINVAL;
    struct xfs_mount* slot = NULL;
    for (size_t i = 0; i < XFS_MOUNTS; ++i) {
        if (mounts[i].used && !strcmp(mounts[i].path, path)) return -EBUSY;
        if (!mounts[i].used && !slot) slot = &mounts[i];
    }
    if (!slot) return -EBUSY;
    struct xfs_mount m = {.ops = ops, .ctx = ctx, .size = size};
    uint8_t sb[4096];
    if (disk_read(&m, 0, sb, 512)) return -EIO;
    if (be32(sb) != 0x58465342) return -EINVAL;
    unsigned version = be16(sb+100) & 15;
    if ((version != 4 && version != 5) || !(be16(sb+100) & 0x2000) || (be16(sb+100) & 0x4200)) return -ENOTSUP;
    m.crc = version == 5;
    unsigned blog = sb[120], ilog = sb[122], slog = sb[121];
    m.aglog = sb[124]; m.inoplog = sb[123];
    if (blog < 9 || blog > 16 || ilog < 8 || ilog > 11 || ilog > blog ||
        slog < 9 || slog > 12 || slog > blog || m.inoplog != blog-ilog ||
        !m.aglog || m.aglog > 32 || sb[192] > 16-blog) return -EINVAL;
    m.blocksize = 1u << blog; m.inodesize = 1u << ilog; m.dirsize = m.blocksize << sb[192];
    m.blocks = be64(sb+8); m.agblocks = be32(sb+84); m.agcount = be32(sb+88); m.root = be64(sb+56);
    if (be32(sb+4) != m.blocksize || be16(sb+102) != (1u << slog) || be16(sb+104) != m.inodesize ||
        be16(sb+106) != (1u << m.inoplog) || !m.blocks || m.blocks > size/m.blocksize ||
        !m.agcount || !m.agblocks || m.agblocks > (1ull << m.aglog) ||
        m.agblocks <= (1ull << (m.aglog-1)) ||
        (uint64_t)(m.agcount-1)*m.agblocks >= m.blocks || (uint64_t)m.agcount*m.agblocks < m.blocks || sb[126]) return -EINVAL;
    if (be64(sb+16) || !be64(sb+48)) return -ENOTSUP; /* realtime/external log */
    uint32_t incompat = m.crc ? be32(sb+216) : 0;
    if (incompat & ~0xefu) return -ENOTSUP; /* includes NEEDSREPAIR */
    m.ftype = m.crc ? (incompat & 1) != 0 : (be32(sb+200) & 0x200) != 0;
    memcpy(m.uuid, sb+((incompat & 4) ? 248 : 32), 16);
    if (m.crc) {
        if (disk_read(&m, 0, sb, 1u << slog) || !crc_ok(sb, 1u << slog, 224)) return -EIO;
    }
    struct xfs_inode root;
    int r = inode_read(&m, m.root, &root);
    if (r) return r;
    if ((root.mode & FS_S_IFMT) != FS_S_IFDIR) return -ENOTDIR;
    strcpy(m.path, path); m.used = true;
    *slot = m;
    return 0;
}
int xfs_mount_image_at(const char* path, const uint8_t* image, size_t size, bool read_only) {
    if (!image) return -EINVAL;
    return xfs_mount_storage_at(path, &memory_ops, (void*)image, size, read_only);
}
int xfs_mount_file_at(const char* path, const struct fs_entry* file, bool read_only) {
    if (!file || (file->mode & FS_S_IFMT) != FS_S_IFREG || file->backend == FS_BACKEND_XFS) return -EINVAL;
    /* Callback context must survive this call, but failed mounts publish nothing. */
    struct fs_entry copy = *file;
    int r = xfs_mount_storage_at(path, &file_ops, &copy, file->size, read_only);
    if (!r) {
        struct xfs_mount* m = mount_for(path);
        m->file = copy;
        m->ctx = &m->file;
    }
    return r;
}
