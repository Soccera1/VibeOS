/* Allocation group trees are rebuilt from sorted records inside the current
 * transaction. Root block numbers remain stable; extra free-space tree blocks
 * are exchanged with the AGFL, as required by XFS free-space accounting. */
struct xw_tree {
    uint8_t* records;
    size_t count, capacity;
    uint32_t* nodes;
    size_t nnodes, nodecap;
    unsigned recordsize, keysize;
    uint32_t magic;
};
struct xw_free {
    struct xw_free* next;
    uint32_t start, len;
};
struct xw_ag {
    struct xw_ag* next;
    uint32_t number, length;
    uint8_t *agf, *agi, *agfl;
    struct xw_tree bno, cnt, ino;
    struct xw_free* pending;
    bool free_dirty, inode_dirty;
};
static int vector_grow(void** p, size_t* cap, size_t need, size_t size) {
    if (need <= *cap)
        return 0;
    size_t n = *cap ? *cap * 2 : 16;
    if (n < need)
        n = need;
    if (n > 1048576 || size > SIZE_MAX / n)
        return -EFBIG;
    void* q = kmalloc(n * size);
    if (!q)
        return -ENOMEM;
    if (*p)
        memcpy(q, *p, *cap * size);
    kfree(*p);
    *p = q;
    *cap = n;
    return 0;
}
static int tree_add_node(struct xw_tree* t, uint32_t block) {
    for (size_t i = 0; i < t->nnodes; ++i)
        if (t->nodes[i] == block)
            return -EIO;
    int r = vector_grow((void**)&t->nodes, &t->nodecap, t->nnodes + 1, sizeof(uint32_t));
    if (!r)
        t->nodes[t->nnodes++] = block;
    return r;
}
static int tree_load_node(struct xfs_mount* m, struct xw_ag* ag, struct xw_tree* t, uint32_t block, unsigned level) {
    if (!block || block >= ag->length || !level || level > 8)
        return -EIO;
    int r = tree_add_node(t, block);
    if (r)
        return r;
    uint64_t off = ((uint64_t)ag->number * m->agblocks + block) * 4096;
    uint8_t* p = kmalloc(4096);
    if (!p)
        return -ENOMEM;
    r = disk_read(m, off, p, 4096);
    if (!r && (be32(p) != t->magic || be16(p + 4) != level - 1 || be64(p + 16) != off / 512 ||
               memcmp(p + 32, m->uuid, 16) || be32(p + 48) != ag->number || !crc_ok(p, 4096, 52)))
        r = -EIO;
    size_t count = be16(p + 6), cap = (4096 - 56) / (level == 1 ? t->recordsize : t->keysize + 4);
    if (count > cap || (level > 1 && !count))
        r = -EIO;
    if (!r && level == 1) {
        r = vector_grow((void**)&t->records, &t->capacity, t->count + count, t->recordsize);
        if (!r) {
            memcpy(t->records + t->count * t->recordsize, p + 56, count * t->recordsize);
            t->count += count;
        }
    } else if (!r) {
        for (size_t i = 0; i < count && !r; ++i)
            r = tree_load_node(m, ag, t, be32(p + 56 + cap * t->keysize + i * 4), level - 1);
    }
    kfree(p);
    return r;
}
static void tree_dispose(struct xw_tree* t) {
    kfree(t->records);
    kfree(t->nodes);
}
static void allocation_discard(struct xfs_transaction* t) {
    while (t->ags) {
        struct xw_ag* a = t->ags;
        t->ags = a->next;
        tree_dispose(&a->bno);
        tree_dispose(&a->cnt);
        tree_dispose(&a->ino);
        while (a->pending) {
            struct xw_free* p = a->pending;
            a->pending = p->next;
            kfree(p);
        }
        kfree(a);
    }
}
static struct xw_ag* ag_load(struct xfs_mount* m, uint32_t number) {
    struct xfs_transaction* tx = m->transaction;
    for (struct xw_ag* a = tx->ags; a; a = a->next)
        if (a->number == number)
            return a;
    struct xw_ag* a = kmalloc(sizeof(*a));
    if (!a) {
        tx->error = -ENOMEM;
        return NULL;
    }
    memset(a, 0, sizeof(*a));
    a->number = number;
    a->next = tx->ags;
    tx->ags = a;
    uint64_t base = (uint64_t)number * m->agblocks * 4096;
    a->agf = edit_buffer(m, base + 512, 512, 5);
    a->agi = edit_buffer(m, base + 1024, 512, 7);
    a->agfl = edit_buffer(m, base + 1536, 512, 6);
    if (!a->agf || !a->agi || !a->agfl)
        return NULL;
    a->length = be32(a->agf + 12);
    if (be32(a->agf) != 0x58414746 || be32(a->agi) != 0x58414749 || be32(a->agfl) != 0x5841464c ||
        be32(a->agf + 8) != number || be32(a->agi + 8) != number || be32(a->agfl + 4) != number || !a->length ||
        a->length > m->agblocks || be32(a->agi + 12) != a->length || memcmp(a->agf + 64, m->uuid, 16) ||
        memcmp(a->agi + 296, m->uuid, 16) || memcmp(a->agfl + 8, m->uuid, 16) || !crc_ok(a->agf, 512, 216) ||
        !crc_ok(a->agi, 512, 312) || !crc_ok(a->agfl, 512, 32) || be32(a->agf + 40) >= 119 ||
        be32(a->agf + 44) >= 119 || be32(a->agf + 48) > 119) {
        tx->error = -EIO;
        return NULL;
    }
    a->bno = (struct xw_tree){.recordsize = 8, .keysize = 8, .magic = 0x41423342};
    a->cnt = (struct xw_tree){.recordsize = 8, .keysize = 8, .magic = 0x41423343};
    a->ino = (struct xw_tree){.recordsize = 16, .keysize = 4, .magic = 0x49414233};
    int r = tree_load_node(m, a, &a->bno, be32(a->agf + 16), be32(a->agf + 28));
    if (!r)
        r = tree_load_node(m, a, &a->cnt, be32(a->agf + 20), be32(a->agf + 32));
    if (!r)
        r = tree_load_node(m, a, &a->ino, be32(a->agi + 20), be32(a->agi + 24));
    uint64_t sum = 0, end = 0;
    for (size_t i = 0; !r && i < a->bno.count; ++i) {
        const uint8_t* p = a->bno.records + i * 8;
        uint32_t start = be32(p), len = be32(p + 4);
        if (!len || start < end || start >= a->length || len > a->length - start)
            r = -EIO;
        end = (uint64_t)start + len;
        sum += len;
    }
    if (!r && (sum != be32(a->agf + 52) || a->cnt.count != a->bno.count))
        r = -EIO;
    if (r) {
        tx->error = r;
        return NULL;
    }
    return a;
}
static int sb_add(struct xfs_mount* m, size_t at, int64_t delta) {
    uint8_t* sb = edit_buffer(m, 0, 512, 18);
    if (!sb)
        return m->transaction->error;
    uint64_t v = be64(sb + at);
    if ((delta < 0 && v < (uint64_t)-delta) || (delta > 0 && v > UINT64_MAX - (uint64_t)delta))
        return -EIO;
    w64(sb + at, v + delta);
    crc_set(sb, 512, 224);
    return 0;
}
static int free_take(struct xw_ag* a, uint32_t count, uint32_t align, uint32_t* block) {
    struct xw_tree* t = &a->bno;
    for (size_t i = 0; i < t->count; ++i) {
        uint8_t* p = t->records + i * 8;
        uint32_t start = be32(p), len = be32(p + 4), chosen = (start + align - 1) & ~(align - 1);
        if (chosen < start || chosen - start > len || count > len - (chosen - start))
            continue;
        uint32_t prefix = chosen - start, suffix = len - prefix - count;
        if (prefix && suffix) {
            int r = vector_grow((void**)&t->records, &t->capacity, t->count + 1, 8);
            if (r)
                return r;
            p = t->records + i * 8;
            memmove(p + 16, p + 8, (t->count - i - 1) * 8);
            ++t->count;
            w32(p + 8, chosen + count);
            w32(p + 12, suffix);
            w32(p + 4, prefix);
        } else if (prefix)
            w32(p + 4, prefix);
        else if (suffix) {
            w32(p, chosen + count);
            w32(p + 4, suffix);
        } else {
            memmove(p, p + 8, (t->count - i - 1) * 8);
            --t->count;
        }
        w32(a->agf + 52, be32(a->agf + 52) - count);
        a->free_dirty = true;
        *block = chosen;
        return 0;
    }
    return -ENOSPC;
}
static int free_insert(struct xw_ag* a, uint32_t start, uint32_t len) {
    struct xw_tree* t = &a->bno;
    if (!len || start >= a->length || len > a->length - start)
        return -EIO;
    size_t i = 0;
    while (i < t->count && be32(t->records + i * 8) < start)
        ++i;
    if ((i && (uint64_t)be32(t->records + (i - 1) * 8) + be32(t->records + (i - 1) * 8 + 4) > start) ||
        (i < t->count && (uint64_t)start + len > be32(t->records + i * 8)))
        return -EIO;
    int r = vector_grow((void**)&t->records, &t->capacity, t->count + 1, 8);
    if (r)
        return r;
    memmove(t->records + (i + 1) * 8, t->records + i * 8, (t->count - i) * 8);
    ++t->count;
    w32(t->records + i * 8, start);
    w32(t->records + i * 8 + 4, len);
    if (i && be32(t->records + (i - 1) * 8) + be32(t->records + (i - 1) * 8 + 4) == start) {
        uint8_t* p = t->records + (i - 1) * 8;
        w32(p + 4, be32(p + 4) + len);
        memmove(p + 8, p + 16, (t->count - i - 1) * 8);
        --t->count;
        --i;
    }
    uint8_t* p = t->records + i * 8;
    if (i + 1 < t->count && be32(p) + be32(p + 4) == be32(p + 8)) {
        w32(p + 4, be32(p + 4) + be32(p + 12));
        memmove(p + 8, p + 16, (t->count - i - 2) * 8);
        --t->count;
    }
    w32(a->agf + 52, be32(a->agf + 52) + len);
    a->free_dirty = true;
    return 0;
}
static int block_allocate(struct xfs_mount* m, uint32_t count, uint32_t align, int64_t preferred, uint64_t* fsb) {
    for (uint32_t i = 0; i < m->agcount; ++i) {
        uint32_t agno = preferred < 0 ? i : ((uint32_t)preferred + i) % m->agcount;
        struct xw_ag* a = ag_load(m, agno);
        if (!a)
            return m->transaction->error;
        uint32_t block;
        int r = free_take(a, count, align, &block);
        if (r == -ENOSPC)
            continue;
        if (r)
            return r;
        *fsb = (uint64_t)agno << m->aglog | block;
        return sb_add(m, 144, -(int64_t)count);
    }
    return -ENOSPC;
}
static int block_release(struct xfs_mount* m, uint64_t fsb, uint32_t count) {
    uint64_t off;
    if (block_offset(m, fsb, &off))
        return -EIO;
    struct xw_ag* a = ag_load(m, fsb >> m->aglog);
    if (!a)
        return m->transaction->error;
    uint32_t block = fsb & ((1ull << m->aglog) - 1);
    if (!count || count > a->length - block || !writable_range(m, off, (size_t)count * 4096))
        return -EIO;
    struct xw_free* p = kmalloc(sizeof(*p));
    if (!p)
        return -ENOMEM;
    *p = (struct xw_free){a->pending, block, count};
    a->pending = p;
    return sb_add(m, 144, count);
}
static size_t tree_shape(struct xw_tree* t, size_t levels[8], unsigned* height) {
    size_t n = (t->count + (4096 - 56) / t->recordsize - 1) / ((4096 - 56) / t->recordsize);
    if (!n)
        n = 1;
    size_t total = n;
    *height = 1;
    levels[0] = n;
    while (n > 1 && *height < 8) {
        size_t cap = (4096 - 56) / (t->keysize + 4);
        n = (n + cap - 1) / cap;
        levels[(*height)++] = n;
        total += n;
    }
    return n == 1 ? total : SIZE_MAX;
}
static int tree_resize(struct xfs_mount* m, struct xw_ag* a, struct xw_tree* t, bool freespace) {
    size_t levels[8];
    unsigned height;
    size_t need = tree_shape(t, levels, &height);
    if (need > XW_MAX_BUFFERS / 2)
        return -EFBIG;
    while (t->nnodes < need) {
        uint32_t block;
        if (freespace && be32(a->agf + 48)) {
            uint32_t head = be32(a->agf + 40);
            block = be32(a->agfl + 36 + head * 4);
            if (!block || block >= a->length)
                return -EIO;
            w32(a->agfl + 36 + head * 4, UINT32_MAX);
            w32(a->agf + 40, (head + 1) % 119);
            w32(a->agf + 48, be32(a->agf + 48) - 1);
        } else {
            int r = free_take(a, 1, 1, &block);
            if (r)
                return r;
            if (!freespace && (r = sb_add(m, 144, -1)))
                return r;
        }
        if (freespace)
            w32(a->agf + 60, be32(a->agf + 60) + 1);
        int r = tree_add_node(t, block);
        if (r)
            return r;
    }
    while (t->nnodes > need) {
        uint32_t block = t->nodes[--t->nnodes];
        if (freespace) {
            if (be32(a->agf + 48) == 119)
                return -ENOSPC;
            uint32_t tail = (be32(a->agf + 44) + 1) % 119;
            w32(a->agfl + 36 + tail * 4, block);
            w32(a->agf + 44, tail);
            w32(a->agf + 48, be32(a->agf + 48) + 1);
            w32(a->agf + 60, be32(a->agf + 60) - 1);
        } else {
            int r = block_release(m, (uint64_t)a->number << m->aglog | block, 1);
            if (r)
                return r;
        }
    }
    return 0;
}
static void short_header(struct xfs_mount* m, struct xw_ag* a, uint8_t* p, uint32_t block, uint32_t magic,
                         unsigned level, unsigned count, uint32_t left, uint32_t right) {
    memset(p, 0, 4096);
    w32(p, magic);
    w16(p + 4, level);
    w16(p + 6, count);
    w32(p + 8, left);
    w32(p + 12, right);
    w64(p + 16, ((uint64_t)a->number * m->agblocks + block) * 8);
    memcpy(p + 32, m->uuid, 16);
    w32(p + 48, a->number);
}
/* Leaves and internal nodes are spread evenly to preserve minimum occupancy. */
static int tree_store(struct xfs_mount* m, struct xw_ag* a, struct xw_tree* t, uint8_t* level_field) {
    size_t shape[8];
    unsigned height;
    size_t total = tree_shape(t, shape, &height);
    if (total != t->nnodes)
        return -EIO;
    uint32_t* order = kmalloc(total * sizeof(uint32_t));
    uint8_t* keys = kmalloc(total * t->keysize);
    if (!order || !keys) {
        kfree(order);
        kfree(keys);
        return -ENOMEM;
    }
    /* Keep the original root at the top. Other nodes need no stable role. */
    for (size_t i = 0; i + 1 < total; ++i)
        order[i] = t->nodes[i + 1];
    order[total - 1] = t->nodes[0];
    size_t base = 0, prevbase = 0, prevcount = t->count;
    int r = 0;
    for (unsigned level = 0; level < height && !r; ++level) {
        size_t consumed = 0;
        for (size_t i = 0; i < shape[level] && !r; ++i) {
            size_t count = prevcount / shape[level] + (i < prevcount % shape[level]);
            uint32_t block = order[base + i];
            uint8_t* p = edit_buffer(m, ((uint64_t)a->number * m->agblocks + block) * 4096, 4096, 4);
            if (!p) {
                r = m->transaction->error;
                break;
            }
            short_header(m, a, p, block, t->magic, level, count, i ? order[base + i - 1] : UINT32_MAX,
                         i + 1 < shape[level] ? order[base + i + 1] : UINT32_MAX);
            if (!level) {
                if (count) {
                    memcpy(p + 56, t->records + consumed * t->recordsize, count * t->recordsize);
                    memcpy(keys + (base + i) * t->keysize, p + 56, t->keysize);
                }
            } else {
                size_t cap = (4096 - 56) / (t->keysize + 4);
                for (size_t j = 0; j < count; ++j) {
                    memcpy(p + 56 + j * t->keysize, keys + (prevbase + consumed + j) * t->keysize, t->keysize);
                    w32(p + 56 + cap * t->keysize + j * 4, order[prevbase + consumed + j]);
                }
                memcpy(keys + (base + i) * t->keysize, p + 56, t->keysize);
            }
            crc_set(p, 4096, 52);
            consumed += count;
        }
        prevbase = base;
        prevcount = shape[level];
        base += shape[level];
    }
    if (!r)
        w32(level_field, height);
    kfree(order);
    kfree(keys);
    return r;
}
static int count_order(const uint8_t* a, const uint8_t* b) {
    uint32_t al = be32(a + 4), bl = be32(b + 4), as = be32(a), bs = be32(b);
    return al < bl ? -1 : al > bl ? 1 : as < bs ? -1 : as > bs;
}
static int allocation_prepare(struct xfs_mount* m) {
    for (struct xw_ag* a = m->transaction->ags; a; a = a->next) {
        int r = 0;
        if (a->inode_dirty) {
            r = tree_resize(m, a, &a->ino, false);
            if (!r)
                r = tree_store(m, a, &a->ino, a->agi + 24);
        }
        while (!r && a->pending) {
            struct xw_free* p = a->pending;
            r = free_insert(a, p->start, p->len);
            a->pending = p->next;
            kfree(p);
        }
        if (!r && a->free_dirty) {
            /* Growing a free-space tree can alter the free record count. */
            for (unsigned attempt = 0; attempt < 8 && !r; ++attempt) {
                a->cnt.count = a->bno.count;
                r = tree_resize(m, a, &a->bno, true);
                if (r)
                    break;
                a->cnt.count = a->bno.count;
                r = tree_resize(m, a, &a->cnt, true);
                if (r)
                    break;
                size_t shape[8];
                unsigned h;
                if (tree_shape(&a->bno, shape, &h) == a->bno.nnodes &&
                    (a->cnt.count = a->bno.count, tree_shape(&a->cnt, shape, &h) == a->cnt.nnodes))
                    break;
                if (attempt == 7)
                    r = -EIO;
            }
            if (!r)
                r = vector_grow((void**)&a->cnt.records, &a->cnt.capacity, a->bno.count, 8);
            if (!r) {
                a->cnt.count = a->bno.count;
                memcpy(a->cnt.records, a->bno.records, a->bno.count * 8);
                for (size_t i = 1; i < a->cnt.count; ++i) {
                    uint8_t tmp[8];
                    memcpy(tmp, a->cnt.records + i * 8, 8);
                    size_t j = i;
                    while (j && count_order(tmp, a->cnt.records + (j - 1) * 8) < 0) {
                        memcpy(a->cnt.records + j * 8, a->cnt.records + (j - 1) * 8, 8);
                        --j;
                    }
                    memcpy(a->cnt.records + j * 8, tmp, 8);
                }
                w32(a->agf + 56, a->cnt.count ? be32(a->cnt.records + (a->cnt.count - 1) * 8 + 4) : 0);
                r = tree_store(m, a, &a->bno, a->agf + 28);
                if (!r)
                    r = tree_store(m, a, &a->cnt, a->agf + 32);
            }
        }
        if (r)
            return r;
        crc_set(a->agf, 512, 216);
        crc_set(a->agi, 512, 312);
        crc_set(a->agfl, 512, 32);
    }
    return 0;
}
static int inode_store(struct xfs_mount* m, struct xfs_inode* ino) {
    if (ino->bytes[82] || be16(ino->bytes + 80))
        return -ENOTSUP;
    if (be16(ino->bytes + 90) & (8 | 16))
        return -1; /* immutable/append-only */
    uint64_t off;
    if (block_offset(m, ino->number >> m->inoplog, &off))
        return -EIO;
    uint8_t* p = edit_buffer(m, off, 4096, 8);
    if (!p)
        return m->transaction->error;
    w16(ino->bytes + 2, ino->mode);
    ino->bytes[5] = ino->format;
    w64(ino->bytes + 56, ino->size);
    w32(ino->bytes + 76, ino->extents);
    stamp_time(ino->bytes + 48);
    w64(ino->bytes + 104, be64(ino->bytes + 104) + 1);
    w64(ino->bytes + 112, 0);
    crc_set(ino->bytes, 512, 100);
    memcpy(p + (ino->number & 7) * 512, ino->bytes, 512);
    return 0;
}
static int inode_allocate(struct xfs_mount* m, uint32_t mode, uint32_t uid, uint32_t gid, struct xfs_inode* ino) {
    for (uint32_t agno = 0; agno < m->agcount; ++agno) {
        struct xw_ag* a = ag_load(m, agno);
        if (!a)
            return m->transaction->error;
        struct xw_tree* t = &a->ino;
        size_t index = 0;
        while (index < t->count && !be32(t->records + index * 16 + 4))
            ++index;
        if (index == t->count) {
            uint32_t block;
            int r = free_take(a, 8, 8, &block);
            if (r == -ENOSPC)
                continue;
            if (r)
                return r;
            r = sb_add(m, 144, -8);
            if (!r)
                r = sb_add(m, 128, 64);
            if (!r)
                r = sb_add(m, 136, 64);
            if (r)
                return r;
            r = vector_grow((void**)&t->records, &t->capacity, t->count + 1, 16);
            if (r)
                return r;
            uint32_t start = block * 8;
            index = 0;
            while (index < t->count && be32(t->records + index * 16) < start)
                ++index;
            memmove(t->records + (index + 1) * 16, t->records + index * 16, (t->count - index) * 16);
            ++t->count;
            uint8_t* rec = t->records + index * 16;
            w32(rec, start);
            w32(rec + 4, 64);
            w64(rec + 8, UINT64_MAX);
            w32(a->agi + 16, be32(a->agi + 16) + 64);
            w32(a->agi + 28, be32(a->agi + 28) + 64);
            w32(a->agi + 32, start);
            for (uint32_t b = 0; b < 8; ++b) {
                uint8_t* p = edit_buffer(m, ((uint64_t)agno * m->agblocks + block + b) * 4096, 4096, 8);
                if (!p)
                    return m->transaction->error;
                memset(p, 0, 4096);
                for (unsigned j = 0; j < 8; ++j) {
                    uint8_t* d = p + j * 512;
                    w16(d, 0x494e);
                    d[4] = 3;
                    d[5] = 2;
                    w32(d + 96, UINT32_MAX);
                    w64(d + 152, ((uint64_t)agno << (m->aglog + 3)) + start + b * 8 + j);
                    memcpy(d + 160, m->uuid, 16);
                    crc_set(d, 512, 100);
                }
            }
        }
        uint8_t* rec = t->records + index * 16;
        uint64_t bits = be64(rec + 8);
        if (!bits || be32(rec + 4) > 64)
            return -EIO;
        unsigned bit = 0;
        while (!(bits & (1ull << bit)))
            ++bit;
        uint64_t number = ((uint64_t)agno << (m->aglog + 3)) + be32(rec) + bit;
        int r = inode_read(m, number, ino);
        if (r)
            return r;
        if (ino->mode || be32(ino->bytes + 16))
            return -EIO;
        uint32_t generation = be32(ino->bytes + 92) + 1;
        memset(ino->bytes, 0, sizeof(ino->bytes));
        ino->number = number;
        ino->mode = mode;
        ino->format = 2;
        ino->core = 176;
        ino->fork = 336;
        ino->size = ino->extents = 0;
        w16(ino->bytes, 0x494e);
        ino->bytes[4] = 3;
        ino->bytes[83] = 2;
        w32(ino->bytes + 8, uid);
        w32(ino->bytes + 12, gid);
        w32(ino->bytes + 16, 1);
        w32(ino->bytes + 92, generation);
        w32(ino->bytes + 96, UINT32_MAX);
        stamp_time(ino->bytes + 32);
        stamp_time(ino->bytes + 40);
        stamp_time(ino->bytes + 144);
        w64(ino->bytes + 152, number);
        memcpy(ino->bytes + 160, m->uuid, 16);
        w64(rec + 8, bits & ~(1ull << bit));
        w32(rec + 4, be32(rec + 4) - 1);
        w32(a->agi + 28, be32(a->agi + 28) - 1);
        a->inode_dirty = true;
        return sb_add(m, 136, -1);
    }
    return -ENOSPC;
}
static int inode_release(struct xfs_mount* m, struct xfs_inode* ino) {
    struct xw_ag* a = ag_load(m, ino->number >> (m->aglog + 3));
    if (!a)
        return m->transaction->error;
    uint32_t agino = ino->number & ((1ull << (m->aglog + 3)) - 1);
    for (size_t i = 0; i < a->ino.count; ++i) {
        uint8_t* p = a->ino.records + i * 16;
        uint32_t start = be32(p);
        if (agino < start || agino - start >= 64)
            continue;
        uint64_t mask = 1ull << (agino - start), bits = be64(p + 8);
        if (bits & mask || be32(p + 4) >= 64)
            return -EIO;
        w64(p + 8, bits | mask);
        w32(p + 4, be32(p + 4) + 1);
        w32(a->agi + 28, be32(a->agi + 28) + 1);
        a->inode_dirty = true;
        ino->mode = 0;
        ino->format = 2;
        ino->size = ino->extents = 0;
        memset(ino->bytes + 176, 0, 336);
        w32(ino->bytes + 96, UINT32_MAX);
        w32(ino->bytes + 16, 0);
        w64(ino->bytes + 64, 0);
        int r = inode_store(m, ino);
        return r ? r : sb_add(m, 136, 1);
    }
    return -EIO;
}
