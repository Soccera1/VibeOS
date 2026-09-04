/* Native XFS metadata transactions. Included by xfs.c to share its checked
 * geometry, inode, directory and extent readers. */
#ifndef CONFIG_KERNEL_XFS_WRITE
static void transaction_overlay(struct xfs_mount* m, uint64_t off, void* p, size_t n) {
    (void)m;
    (void)off;
    (void)p;
    (void)n;
}
static int writable_mount(struct xfs_mount* m, const uint8_t* sb) {
    (void)m;
    (void)sb;
    return -EROFS;
}
int xfs_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count) {
    (void)entry;
    (void)offset;
    (void)buf;
    (void)count;
    return -EROFS;
}
int xfs_truncate(struct fs_entry* entry, size_t size) {
    (void)entry;
    (void)size;
    return -EROFS;
}
int xfs_create(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    (void)path;
    (void)mode;
    (void)uid;
    (void)gid;
    (void)out;
    return -EROFS;
}
int xfs_mknod(const char* path, uint32_t mode, uint32_t rdev, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    (void)path;
    (void)mode;
    (void)rdev;
    (void)uid;
    (void)gid;
    (void)out;
    return -EROFS;
}
int xfs_mkdir(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    (void)path;
    (void)mode;
    (void)uid;
    (void)gid;
    (void)out;
    return -EROFS;
}
int xfs_symlink(const char* target, const char* linkpath, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    (void)target;
    (void)linkpath;
    (void)uid;
    (void)gid;
    (void)out;
    return -EROFS;
}
int xfs_link(const char* existing, const char* newpath) {
    (void)existing;
    (void)newpath;
    return -EROFS;
}
int xfs_unlink(const char* path) {
    (void)path;
    return -EROFS;
}
int xfs_rmdir(const char* path) {
    (void)path;
    return -EROFS;
}
int xfs_rename(const char* oldpath, const char* newpath) {
    (void)oldpath;
    (void)newpath;
    return -EROFS;
}
int xfs_chmod(const char* path, uint32_t mode) {
    (void)path;
    (void)mode;
    return -EROFS;
}
int xfs_chown(const char* path, uint32_t uid, uint32_t gid) {
    (void)path;
    (void)uid;
    (void)gid;
    return -EROFS;
}
int xfs_utime(const char* path, uint32_t atime, uint32_t mtime) {
    (void)path;
    (void)atime;
    (void)mtime;
    return -EROFS;
}
int xfs_change_metadata_entry(const struct fs_entry* entry, unsigned operation, uint32_t a, uint32_t b) {
    (void)entry;
    (void)operation;
    (void)a;
    (void)b;
    return -EROFS;
}
int xfs_sync_all(void) { return 0; }
void xfs_set_inode_busy_checker(bool (*checker)(const char*, uint64_t)) { (void)checker; }
#else
#if !__STDC_HOSTED__
#include "io.h"
#include "syscall.h"
#else
#include <time.h>
#endif
#define ENOSPC 28
#define EEXIST 17
#define EXDEV 18
#define EISDIR 21
#define ENOTEMPTY 39
#define EFBIG 27
#define EMLINK 31
#define XW_MAX_BUFFERS 1024
#define XW_LOG_MAGIC 0xfeedbabeu
struct xfs_buffer {
    struct xfs_buffer* next;
    uint64_t off;
    size_t len;
    unsigned type;
    uint8_t data[];
};
struct xfs_transaction {
    struct xfs_buffer* buffers;
    struct xw_ag* ags;
    unsigned count;
    uint64_t irq;
    int error;
};
static void w16(uint8_t* p, uint16_t v) {
    p[0] = v >> 8;
    p[1] = v;
}
static void w32(uint8_t* p, uint32_t v) {
    w16(p, v >> 16);
    w16(p + 2, v);
}
static void w64(uint8_t* p, uint64_t v) {
    w32(p, v >> 32);
    w32(p + 4, v);
}
static void l16(uint8_t* p, uint16_t v) {
    p[0] = v;
    p[1] = v >> 8;
}
static void l32(uint8_t* p, uint32_t v) {
    l16(p, v);
    l16(p + 2, v >> 16);
}
static void l64(uint8_t* p, uint64_t v) {
    l32(p, v);
    l32(p + 4, v >> 32);
}
static uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const uint8_t* p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }
static uint32_t crc_update(uint32_t crc, const uint8_t* p, size_t n) {
    while (n--) {
        crc ^= *p++;
        for (unsigned b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0x82f63b78u & (0u - (crc & 1)));
    }
    return crc;
}
static void crc_set(uint8_t* p, size_t n, size_t at) {
    memset(p + at, 0, 4);
    l32(p + at, ~crc_update(~0u, p, n));
}
static void stamp_time(uint8_t* p) {
#if __STDC_HOSTED__
    time_t seconds = time(NULL);
    uint64_t ns = seconds < 0 ? 0 : (uint64_t)seconds * 1000000000;
#else
    uint64_t ns = syscall_wall_time_ns();
#endif
    w32(p, ns / 1000000000);
    w32(p + 4, ns % 1000000000);
}
static void transaction_overlay(struct xfs_mount* m, uint64_t off, void* p, size_t n) {
    if (!m->transaction)
        return;
    for (struct xfs_buffer* b = m->transaction->buffers; b; b = b->next) {
        uint64_t start = off > b->off ? off : b->off, end = off + n < b->off + b->len ? off + n : b->off + b->len;
        if (start < end)
            memcpy((uint8_t*)p + start - off, b->data + start - b->off, end - start);
    }
}
static bool writable_range(struct xfs_mount* m, uint64_t off, size_t len) {
    return len && !(off % 512) && !(len % 512) && off <= m->size && len <= m->size - off &&
           (off + len <= m->logoff || off >= m->logoff + m->logbytes);
}
static int raw_write(struct xfs_mount* m, uint64_t off, const void* p, size_t n) {
    if (m->failed || off > m->size || n > m->size - off || m->ops->write(m->ctx, off, p, n)) {
        m->failed = true;
        return -EIO;
    }
    return 0;
}
static int durable(struct xfs_mount* m) {
    if (m->failed || m->ops->flush(m->ctx)) {
        m->failed = true;
        return -EIO;
    }
    return 0;
}
/* A buffer is either an AG sector or a complete filesystem block. Overlapping
 * buffers with different sizes are forbidden, so there is one final image. */
static uint8_t* edit_buffer(struct xfs_mount* m, uint64_t off, size_t n, unsigned type) {
    struct xfs_transaction* t = m->transaction;
    if (!t || t->error)
        return NULL;
    if (!writable_range(m, off, n) || n > 4096 || type > 18) {
        t->error = -EIO;
        return NULL;
    }
    for (struct xfs_buffer* b = t->buffers; b; b = b->next) {
        if (off == b->off && n == b->len && type == b->type)
            return b->data;
        if (off < b->off + b->len && b->off < off + n) {
            t->error = -EIO;
            return NULL;
        }
    }
    if (t->count == XW_MAX_BUFFERS) {
        t->error = -EFBIG;
        return NULL;
    }
    struct xfs_buffer* b = kmalloc(sizeof(*b) + n);
    if (!b) {
        t->error = -ENOMEM;
        return NULL;
    }
    if (disk_read(m, off, b->data, n)) {
        kfree(b);
        t->error = -EIO;
        return NULL;
    }
    b->off = off;
    b->len = n;
    b->type = type;
    b->next = t->buffers;
    t->buffers = b;
    ++t->count;
    return b->data;
}
static int transaction_begin(struct xfs_mount* m) {
    if (!m || !m->writable)
        return -EROFS;
    if (m->failed)
        return -EIO;
    uint64_t irq = 0;
#if !__STDC_HOSTED__
    irq = irq_save();
#endif
    if (m->transaction) {
#if !__STDC_HOSTED__
        irq_restore(irq);
#endif
        return -EBUSY;
    }
    struct xfs_transaction* t = kmalloc(sizeof(*t));
    if (!t) {
#if !__STDC_HOSTED__
        irq_restore(irq);
#endif
        return -ENOMEM;
    }
    memset(t, 0, sizeof(*t));
    t->irq = irq;
    m->transaction = t;
    return 0;
}
static void allocation_discard(struct xfs_transaction*);
static int allocation_prepare(struct xfs_mount*);
static void transaction_discard(struct xfs_mount* m) {
    struct xfs_transaction* t = m->transaction;
    while (t->buffers) {
        struct xfs_buffer* b = t->buffers;
        t->buffers = b->next;
        kfree(b);
    }
    allocation_discard(t);
    uint64_t irq = t->irq;
    m->transaction = NULL;
    kfree(t);
#if !__STDC_HOSTED__
    irq_restore(irq);
#else
    (void)irq;
#endif
}
static uint64_t log_advance(struct xfs_mount* m, uint64_t lsn, size_t sectors) {
    uint64_t cycle = lsn >> 32, block = (uint32_t)lsn;
    block += sectors;
    if (block >= m->logbytes / 512) {
        block -= m->logbytes / 512;
        ++cycle;
    }
    /* The magic number is not a valid cycle. */
    if (cycle == XW_LOG_MAGIC)
        ++cycle;
    return cycle << 32 | block;
}
static int log_io(struct xfs_mount* m, uint64_t lsn, void* p, size_t n, bool write) {
    size_t pos = (uint32_t)lsn * 512ull, first = m->logbytes - pos;
    if (first > n)
        first = n;
    int r = write ? raw_write(m, m->logoff + pos, p, first) : m->ops->read(m->ctx, m->logoff + pos, p, first);
    if (!r && first < n)
        r = write ? raw_write(m, m->logoff, (uint8_t*)p + first, n - first)
                  : m->ops->read(m->ctx, m->logoff, (uint8_t*)p + first, n - first);
    return r ? -EIO : 0;
}
static uint32_t log_crc(uint8_t* record, size_t len) {
    uint32_t saved = le32(record + 32);
    l32(record + 32, 0);
    uint32_t crc = crc_update(~0u, record, 328);
    crc = ~crc_update(crc, record + 512, len);
    l32(record + 32, saved);
    return crc;
}
static size_t log_op(uint8_t* p, uint32_t tid, uint8_t flags, const void* data, size_t n) {
    w32(p, tid);
    w32(p + 4, n);
    p[8] = flags == 0x20 ? 0xaa : 0x69;
    p[9] = flags;
    w16(p + 10, 0);
    if (n)
        memcpy(p + 12, data, n);
    return 12 + n;
}
/* Each log record fits one cycle-data header. Regions never straddle records;
 * a transaction can contain many records and has a separate commit record. */
static int log_emit(struct xfs_mount* m, uint8_t* record, size_t len, unsigned ops, uint64_t tail) {
    size_t padded = (len + 511) & ~(size_t)511;
    if (!len || padded > 32768 || !m->lognext || (m->lognext >> 32) > UINT32_MAX)
        return -EIO;
    memset(record, 0, 512);
    memset(record + 512 + len, 0, padded - len);
    uint64_t lsn = m->lognext;
    w32(record, XW_LOG_MAGIC);
    w32(record + 4, lsn >> 32);
    w32(record + 8, 2);
    w32(record + 12, padded);
    w64(record + 16, lsn);
    w64(record + 24, tail);
    w32(record + 36, m->logprev);
    w32(record + 40, ops);
    w32(record + 300, 1);
    memcpy(record + 304, m->uuid, 16);
    w32(record + 320, 32768);
    for (size_t i = 0; i < padded / 512; ++i) {
        memcpy(record + 44 + i * 4, record + 512 + i * 512, 4);
        w32(record + 512 + i * 512, log_advance(m, lsn, i + 1) >> 32);
    }
    l32(record + 32, log_crc(record, padded));
    /* Persist the header before its payload, and complete each record before
     * beginning the next. Recovery can then cover one incomplete record even
     * when the device persists its payload sectors out of order. */
    int r = log_io(m, lsn, record, 512, true);
    if (!r)
        r = durable(m);
    if (!r)
        r = log_io(m, log_advance(m, lsn, 1), record + 512, padded, true);
    if (!r)
        r = durable(m);
    if (!r) {
        m->logprev = (uint32_t)lsn;
        m->lognext = log_advance(m, lsn, 1 + padded / 512);
    }
    return r;
}
static int log_clean(struct xfs_mount* m, uint8_t* record) {
    uint8_t pending[512];
    size_t reserved = 0;
    if (log_io(m, m->lognext, pending, 512, false))
        return -EIO;
    if (be32(pending) == XW_LOG_MAGIC && be64(pending + 16) == m->lognext) {
        reserved = be32(pending + 12);
        if (!reserved || reserved > 32768 || reserved % 512)
            return -EIO;
    }
    /* Cover the complete torn record. Leaving its cycle-stamped sectors
     * beyond a shorter unmount record confuses the native log head search. */
    memset(record + 512, 0, 32768);
    uint8_t unmount[8] = {0x6e, 0x55};
    size_t n = log_op(record + 512, 0, 0x20, unmount, sizeof(unmount));
    if (reserved > n)
        n = reserved;
    int r = log_emit(m, record, n, 1, m->lognext);
    return r ? r : durable(m);
}
static int transaction_commit(struct xfs_mount* m) {
    struct xfs_transaction* t = m->transaction;
    int r = t->error;
    if (!r)
        r = allocation_prepare(m);
    unsigned metadata = 0;
    size_t sectors = 6; /* transaction header, commit and clean marker */
    for (struct xfs_buffer* b = t->buffers; b; b = b->next)
        if (b->type) {
            ++metadata;
            sectors += 1 + (b->len + 48 + 511) / 512;
        }
    uint8_t* rec = NULL;
    if (!r && sectors >= m->logbytes / 1024)
        r = -EFBIG;
    if (!r && !(rec = kmalloc(512 + 32768)))
        r = -ENOMEM;
    /* Newly allocated data reaches disk before allocation metadata can commit. */
    for (struct xfs_buffer* b = t->buffers; !r && b; b = b->next)
        if (!b->type)
            r = raw_write(m, b->off, b->data, b->len);
    if (!r)
        r = durable(m);
    uint64_t tail = m->lognext;
    uint32_t tid = (uint32_t)tail ^ (uint32_t)(tail >> 32);
    if (!r && metadata) {
        uint8_t th[16];
        l32(th, 0x5452414e);
        l32(th + 4, 40);
        l32(th + 8, tid);
        l32(th + 12, metadata);
        size_t n = log_op(rec + 512, tid, 1, NULL, 0);
        n += log_op(rec + 512 + n, tid, 0, th, sizeof(th));
        r = log_emit(m, rec, n, 2, tail);
    }
    for (struct xfs_buffer* b = t->buffers; !r && metadata && b; b = b->next)
        if (b->type) {
            uint8_t fmt[24] = {0};
            l16(fmt, 0x123c);
            l16(fmt + 2, 2);
            l16(fmt + 4, b->type << 11);
            l16(fmt + 6, b->len / 512);
            l64(fmt + 8, b->off / 512);
            l32(fmt + 16, 1);
            l32(fmt + 20, b->len == 4096 ? UINT32_MAX : (1u << (b->len / 128)) - 1);
            size_t n = log_op(rec + 512, tid, 0, fmt, sizeof(fmt));
            n += log_op(rec + 512 + n, tid, 0, b->data, b->len);
            r = log_emit(m, rec, n, 2, tail);
        }
    /* Do not allow the commit sector to become durable ahead of its items. */
    if (!r && metadata)
        r = durable(m);
    if (!r && metadata)
        r = log_emit(m, rec, log_op(rec + 512, tid, 2, NULL, 0), 1, tail);
    if (!r && metadata)
        r = durable(m);
    for (struct xfs_buffer* b = t->buffers; !r && metadata && b; b = b->next)
        if (b->type)
            r = raw_write(m, b->off, b->data, b->len);
    if (!r && metadata)
        r = durable(m);
    if (!r && metadata)
        r = log_clean(m, rec);
    kfree(rec);
    transaction_discard(m);
    return r;
}
/* 1: complete valid record, 0: incomplete/torn tail, negative: I/O failure. */
static int log_load(struct xfs_mount* m, uint64_t block, uint8_t* rec) {
    if (m->ops->read(m->ctx, m->logoff + block * 512, rec, 512))
        return -EIO;
    size_t len = be32(rec + 12);
    uint64_t lsn = be64(rec + 16);
    if (be32(rec) != XW_LOG_MAGIC || !be32(rec + 4) || memcmp(rec + 304, m->uuid, 16) || (uint32_t)lsn != block ||
        (lsn >> 32) != be32(rec + 4))
        return 0;
    if (be32(rec + 8) != 2 || len > 32768 || be32(rec + 300) != 1 || be32(rec + 320) != 32768)
        return -ENOTSUP;
    if (!len || len % 512)
        return 0;
    if (log_io(m, log_advance(m, lsn, 1), rec + 512, len, false))
        return -EIO;
    if (le32(rec + 32) != log_crc(rec, len)) {
        /* mkfs's initial unmount record has no checksum. */
        if (le32(rec + 32) || lsn != 0x100000000ull || be32(rec + 40) != 1 || len != 512 || rec[520] != 0xaa ||
            rec[521] != 0x20 || rec[524] != 0x6e || rec[525] != 0x55)
            return 0;
    }
    for (size_t i = 0; i < len / 512; ++i) {
        if (be32(rec + 512 + i * 512) != (log_advance(m, lsn, i + 1) >> 32))
            return 0;
        memcpy(rec + 512 + i * 512, rec + 44 + i * 4, 4);
    }
    return 1;
}
static int log_recover(struct xfs_mount* m) {
    uint8_t* rec = kmalloc(512 + 32768);
    if (!rec)
        return -ENOMEM;
    uint64_t latest = 0, tail = 0, candidates[2] = {0};
    size_t lastlen = 0;
    int r = 0;
    /* Headers identify the two newest records. Since each record is durable
     * before the next starts, only the newest can be incomplete. Avoid reading
     * and checksumming the contents of every historical record in a full log. */
    uint8_t* scan = kmalloc(32768);
    if (!scan) {
        kfree(rec);
        return -ENOMEM;
    }
    for (uint64_t off = 0; off < m->logbytes && !r; off += 32768) {
        size_t n = m->logbytes - off < 32768 ? m->logbytes - off : 32768;
        if (m->ops->read(m->ctx, m->logoff + off, scan, n)) {
            r = -EIO;
            break;
        }
        for (size_t at = 0; at < n; at += 512) {
            const uint8_t* h = scan + at;
            uint64_t lsn = be64(h + 16);
            if (be32(h) != XW_LOG_MAGIC || !be32(h + 4) || (lsn >> 32) != be32(h + 4) ||
                (uint32_t)lsn != (off + at) / 512 || memcmp(h + 304, m->uuid, 16))
                continue;
            if (lsn > candidates[0]) {
                candidates[1] = candidates[0];
                candidates[0] = lsn;
            } else if (lsn > candidates[1])
                candidates[1] = lsn;
        }
    }
    kfree(scan);
    for (unsigned i = 0; !r && !latest && i < 2 && candidates[i]; ++i) {
        int valid = log_load(m, (uint32_t)candidates[i], rec);
        if (valid < 0)
            r = valid;
        else if (valid) {
            latest = be64(rec + 16);
            tail = be64(rec + 24);
            lastlen = be32(rec + 12);
        }
    }
    if (!r && (!latest || !tail || tail > latest || (uint32_t)tail >= m->logbytes / 512))
        r = -ENOTSUP;
    if (r) {
        kfree(rec);
        return r;
    }
    m->lognext = log_advance(m, latest, 1 + lastlen / 512);
    m->logprev = (uint32_t)latest;
    /* Parse only complete native buffer transactions. Foreign dirty logs with
     * other item types are refused, never discarded or marked clean. */
    struct xfs_transaction t = {0};
    m->transaction = &t;
    uint32_t tid = 0, expected = 0, received = 0;
    bool started = false, header = false, clean = false;
    uint8_t fmt[24];
    bool have_fmt = false;
    uint64_t cursor = tail, walked = 0;
    while (!r && cursor <= latest) {
        if ((r = log_load(m, (uint32_t)cursor, rec)) != 1 || be64(rec + 16) != cursor) {
            r = -EIO;
            break;
        }
        r = 0;
        unsigned ops = be32(rec + 40);
        size_t pos = 512, end = 512 + be32(rec + 12);
        for (unsigned op = 0; op < ops && !r; ++op) {
            if (end - pos < 12) {
                r = -EIO;
                break;
            }
            uint32_t id = be32(rec + pos), len = be32(rec + pos + 4);
            uint8_t client = rec[pos + 8], flags = rec[pos + 9];
            pos += 12;
            if (len > end - pos) {
                r = -EIO;
                break;
            }
            uint8_t* p = rec + pos;
            if (client == 0xaa && flags == 0x20 && len == 8 && p[0] == 0x6e && p[1] == 0x55 && !started)
                clean = true;
            else if (client != 0x69)
                r = -ENOTSUP;
            else if (flags == 1 && !len && !started) {
                started = true;
                clean = false;
                tid = id;
            } else if (!started || id != tid)
                r = -ENOTSUP;
            else if (flags == 2 && !len && header && !have_fmt && received == expected) {
                /* Replay is idempotent; a second interruption retries this same transaction. */
                for (struct xfs_buffer* b = t.buffers; !r && b; b = b->next)
                    r = raw_write(m, b->off, b->data, b->len);
                if (!r)
                    r = durable(m);
                while (t.buffers) {
                    struct xfs_buffer* b = t.buffers;
                    t.buffers = b->next;
                    kfree(b);
                }
                t.count = 0;
                started = header = false;
                received = 0;
            } else if (flags)
                r = -ENOTSUP;
            else if (!header) {
                if (len != 16 || le32(p) != 0x5452414e || le32(p + 4) != 40)
                    r = -ENOTSUP;
                else {
                    expected = le32(p + 12);
                    header = true;
                    if (expected > XW_MAX_BUFFERS)
                        r = -EIO;
                }
            } else if (!have_fmt) {
                if (len != 24 || p[0] != 0x3c || p[1] != 0x12 || p[2] != 2 || p[3] ||
                    ((p[4] | (unsigned)p[5] << 8) & 0x7ff) || le32(p + 16) != 1)
                    r = -ENOTSUP;
                else {
                    memcpy(fmt, p, 24);
                    have_fmt = true;
                }
            } else {
                unsigned type = (fmt[4] | (unsigned)fmt[5] << 8) >> 11;
                size_t bytes = (fmt[6] | (size_t)fmt[7] << 8) * 512;
                uint64_t blk = le64(fmt + 8);
                if (!type || type > 18 || !bytes || bytes > 4096 || len != bytes || blk > UINT64_MAX / 512 ||
                    le32(fmt + 20) != (bytes == 4096 ? UINT32_MAX : (1u << (bytes / 128)) - 1))
                    r = -EIO;
                else {
                    uint8_t* dst = edit_buffer(m, blk * 512, bytes, type);
                    if (!dst)
                        r = t.error;
                    else
                        memcpy(dst, p, bytes);
                    ++received;
                    have_fmt = false;
                }
            }
            pos += len;
        }
        uint64_t next = log_advance(m, cursor, 1 + be32(rec + 12) / 512);
        walked += 1 + be32(rec + 12) / 512;
        if (walked > m->logbytes / 512 || next <= cursor)
            r = -EIO;
        cursor = next;
    }
    while (t.buffers) {
        struct xfs_buffer* b = t.buffers;
        t.buffers = b->next;
        kfree(b);
    }
    m->transaction = NULL;
    if (!r && clean) {
        uint8_t pending[512];
        if (log_io(m, m->lognext, pending, 512, false))
            r = -EIO;
        else if (be32(pending) == XW_LOG_MAGIC && be64(pending + 16) == m->lognext)
            clean = false;
    }
    if (!r && !clean)
        r = log_clean(m, rec); /* incomplete transactions have no home writes */
    kfree(rec);
    return r;
}
/* Dependency order matters: these are implementation fragments. */
// clang-format off
#include "xfs_alloc.inc"
#include "xfs_file.inc"
#include "xfs_dir.inc"
#include "xfs_mutate.inc"
// clang-format on
static int writable_mount(struct xfs_mount* m, const uint8_t* sb) {
    /* Features whose allocation metadata this writer does not maintain cannot
     * be accepted writable. The reader continues to accept its broader set. */
    if (!m->crc || m->blocksize != 4096 || m->inodesize != 512 || m->dirsize != 4096 || be16(sb + 102) != 512 ||
        be32(sb + 212) || be32(sb + 216) != 1 || be32(sb + 220) || be16(sb + 176) || be32(sb + 196) > 1)
        return -ENOTSUP;
    if (block_offset(m, be64(sb + 48), &m->logoff))
        return -EIO;
    m->logbytes = (uint64_t)be32(sb + 96) * m->blocksize;
    if (m->logbytes < 4 * 1024 * 1024 || m->logoff > m->size || m->logbytes > m->size - m->logoff)
        return -EIO;
    int r = log_recover(m);
    if (!r) {
        m->writable = true;
        m->has_orphans = true;
        r = reap_mount(m);
    }
    return r;
}
#endif

bool xfs_is_read_only_path(const char* path) {
    struct xfs_mount* m = mount_for(path);
    return m && !m->writable;
}
bool xfs_same_file(const struct fs_entry* a, const struct fs_entry* b) {
    return a && b && a->backend == FS_BACKEND_XFS && b->backend == FS_BACKEND_XFS && a->inode == b->inode &&
           mount_for(a->path) && mount_for(a->path) == mount_for(b->path);
}
