struct xw_extent {
    uint64_t logical, fsb;
    uint32_t len;
    bool unwritten;
};
struct xw_map {
    struct xw_extent* ext;
    size_t count, cap;
    uint64_t* nodes;
    size_t nnodes, nodecap;
};
static void map_dispose(struct xw_map* map) {
    kfree(map->ext);
    kfree(map->nodes);
    memset(map, 0, sizeof(*map));
}
static int map_append(struct xw_map* map, struct xw_extent e) {
    if (!e.len || e.logical > (1ull << 54) - e.len)
        return -EIO;
    if (map->count && map->ext[map->count - 1].logical + map->ext[map->count - 1].len > e.logical)
        return -EIO;
    int r = vector_grow((void**)&map->ext, &map->cap, map->count + 1, sizeof(e));
    if (!r)
        map->ext[map->count++] = e;
    return r;
}
static int map_records(struct xfs_mount* m, struct xw_map* map, const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i, p += 16) {
        uint64_t a = be64(p), b = be64(p + 8), off;
        struct xw_extent e = {(a >> 9) & ((1ull << 54) - 1), ((a & 511) << 43) | (b >> 21), b & ((1u << 21) - 1),
                              (a >> 63) != 0};
        if (!e.len || (e.fsb & ((1ull << m->aglog) - 1)) + e.len > m->agblocks ||
            block_offset(m, e.fsb + e.len - 1, &off))
            return -EIO;
        int r = map_append(map, e);
        if (r)
            return r;
    }
    return 0;
}
static int map_node(struct xfs_mount* m, struct xfs_inode* ino, struct xw_map* map, uint64_t fsb, unsigned level) {
    uint64_t off;
    if (block_offset(m, fsb, &off) || level > 7)
        return -EIO;
    for (size_t i = 0; i < map->nnodes; ++i)
        if (map->nodes[i] == fsb)
            return -EIO;
    int r = vector_grow((void**)&map->nodes, &map->nodecap, map->nnodes + 1, 8);
    if (r)
        return r;
    map->nodes[map->nnodes++] = fsb;
    uint8_t* p = kmalloc(4096);
    if (!p)
        return -ENOMEM;
    r = disk_read(m, off, p, 4096);
    size_t n = be16(p + 6), cap = (4096 - 72) / 16;
    if (!r && (be32(p) != 0x424d4133 || be16(p + 4) != level || !n || n > cap || be64(p + 24) != off / 512 ||
               memcmp(p + 40, m->uuid, 16) || be64(p + 56) != ino->number || !crc_ok(p, 4096, 64)))
        r = -EIO;
    if (!r && !level)
        r = map_records(m, map, p + 72, n);
    else
        for (size_t i = 0; !r && i < n; ++i)
            r = map_node(m, ino, map, be64(p + 72 + cap * 8 + i * 8), level - 1);
    kfree(p);
    return r;
}
static int map_load(struct xfs_mount* m, struct xfs_inode* ino, struct xw_map* map) {
    memset(map, 0, sizeof(*map));
    if (ino->bytes[82] || be16(ino->bytes + 80) || be64(ino->bytes + 120))
        return -ENOTSUP;
    int r = 0;
    const uint8_t* p = ino->bytes + 176;
    if (ino->format == 2)
        r = map_records(m, map, p, ino->extents);
    else if (ino->format == 3) {
        unsigned level = be16(p), n = be16(p + 2);
        size_t cap = (ino->fork - 4) / 16;
        if (!level || level > 8 || !n || n > cap)
            r = -EIO;
        else
            for (unsigned i = 0; !r && i < n; ++i)
                r = map_node(m, ino, map, be64(p + 4 + cap * 8 + i * 8), level - 1);
    } else if (ino->format != 1 && ino->format != 0)
        r = -ENOTSUP;
    if (!r && map->count != ino->extents)
        r = -EIO;
    if (r)
        map_dispose(map);
    return r;
}
static void extent_encode(uint8_t* p, const struct xw_extent* e) {
    w64(p, (uint64_t)e->unwritten << 63 | e->logical << 9 | e->fsb >> 43);
    w64(p + 8, e->fsb << 21 | e->len);
}
static void map_merge(struct xfs_mount* m, struct xw_map* map) {
    size_t n = 0;
    for (size_t i = 0; i < map->count; ++i) {
        struct xw_extent* e = &map->ext[i];
        if (n && map->ext[n - 1].logical + map->ext[n - 1].len == e->logical &&
            map->ext[n - 1].fsb + map->ext[n - 1].len == e->fsb &&
            (map->ext[n - 1].fsb >> m->aglog) == (e->fsb >> m->aglog) && map->ext[n - 1].unwritten == e->unwritten &&
            map->ext[n - 1].len + e->len < (1u << 21))
            map->ext[n - 1].len += e->len;
        else
            map->ext[n++] = *e;
    }
    map->count = n;
}
static bool map_get(struct xw_map* map, uint64_t logical, uint64_t* fsb, bool* unwritten) {
    for (size_t i = 0; i < map->count; ++i) {
        struct xw_extent* e = map->ext + i;
        if (logical >= e->logical && logical - e->logical < e->len) {
            *fsb = e->fsb + logical - e->logical;
            *unwritten = e->unwritten;
            return true;
        }
    }
    return false;
}
static int map_set(struct xfs_mount* m, struct xw_map* map, uint64_t logical, uint64_t fsb) {
    int r = vector_grow((void**)&map->ext, &map->cap, map->count + 3, sizeof(*map->ext));
    if (r)
        return r;
    size_t i = 0;
    while (i < map->count && map->ext[i].logical + map->ext[i].len <= logical)
        ++i;
    if (i < map->count && map->ext[i].logical <= logical) {
        struct xw_extent old = map->ext[i];
        size_t prefix = logical - old.logical, suffix = old.len - prefix - 1, parts = 1 + (prefix != 0) + (suffix != 0);
        memmove(map->ext + i + parts, map->ext + i + 1, (map->count - i - 1) * sizeof(*map->ext));
        map->count += parts - 1;
        if (prefix) {
            map->ext[i] = old;
            map->ext[i++].len = prefix;
        }
        map->ext[i++] = (struct xw_extent){logical, fsb, 1, false};
        if (suffix)
            map->ext[i] = (struct xw_extent){logical + 1, old.fsb + prefix + 1, suffix, old.unwritten};
    } else {
        memmove(map->ext + i + 1, map->ext + i, (map->count - i) * sizeof(*map->ext));
        ++map->count;
        map->ext[i] = (struct xw_extent){logical, fsb, 1, false};
    }
    map_merge(m, map);
    return 0;
}
static int map_trim(struct xfs_mount* m, struct xw_map* map, uint64_t blocks) {
    for (size_t i = 0; i < map->count; ++i) {
        struct xw_extent* e = map->ext + i;
        if (e->logical + e->len <= blocks)
            continue;
        uint32_t keep = blocks > e->logical ? blocks - e->logical : 0;
        int r = block_release(m, e->fsb + keep, e->len - keep);
        if (r)
            return r;
        e->len = keep;
    }
    size_t count = 0;
    for (size_t i = 0; i < map->count; ++i)
        if (map->ext[i].len)
            map->ext[count++] = map->ext[i];
    map->count = count;
    return 0;
}
static int map_store(struct xfs_mount* m, struct xfs_inode* ino, struct xw_map* map) {
    size_t shape[8], total = 0;
    unsigned height = 0;
    size_t leafcap = (4096 - 72) / 16, rootcap = (ino->fork - 4) / 16;
    if (map->count > ino->fork / 16) {
        size_t n = (map->count + leafcap - 1) / leafcap;
        do {
            if (height == 8)
                return -EFBIG;
            shape[height++] = n;
            total += n;
            n = (n + leafcap - 1) / leafcap;
        } while (shape[height - 1] > rootcap);
    }
    if (total > XW_MAX_BUFFERS / 2)
        return -EFBIG;
    while (map->nnodes < total) {
        int r = vector_grow((void**)&map->nodes, &map->nodecap, map->nnodes + 1, 8);
        if (r)
            return r;
        uint64_t fsb;
        r = block_allocate(m, 1, 1, ino->number >> (m->aglog + 3), &fsb);
        if (r)
            return r;
        map->nodes[map->nnodes++] = fsb;
    }
    while (map->nnodes > total) {
        int r = block_release(m, map->nodes[--map->nnodes], 1);
        if (r)
            return r;
    }
    uint64_t nblocks = total;
    for (size_t i = 0; i < map->count; ++i)
        nblocks += map->ext[i].len;
    memset(ino->bytes + 176, 0, ino->fork);
    ino->extents = map->count;
    ino->format = height ? 3 : 2;
    w64(ino->bytes + 64, nblocks);
    if (!height)
        for (size_t i = 0; i < map->count; ++i)
            extent_encode(ino->bytes + 176 + i * 16, map->ext + i);
    else {
        uint64_t* keys = kmalloc(total * 8);
        if (!keys)
            return -ENOMEM;
        size_t base = 0, prevbase = 0, prevcount = map->count;
        int r = 0;
        for (unsigned level = 0; level < height && !r; ++level) {
            size_t consumed = 0;
            for (size_t i = 0; i < shape[level]; ++i) {
                size_t count = prevcount / shape[level] + (i < prevcount % shape[level]);
                uint64_t off;
                if (block_offset(m, map->nodes[base + i], &off)) {
                    r = -EIO;
                    break;
                }
                uint8_t* p = edit_buffer(m, off, 4096, 4);
                if (!p) {
                    r = m->transaction->error;
                    break;
                }
                memset(p, 0, 4096);
                w32(p, 0x424d4133);
                w16(p + 4, level);
                w16(p + 6, count);
                w64(p + 8, i ? map->nodes[base + i - 1] : UINT64_MAX);
                w64(p + 16, i + 1 < shape[level] ? map->nodes[base + i + 1] : UINT64_MAX);
                w64(p + 24, off / 512);
                memcpy(p + 40, m->uuid, 16);
                w64(p + 56, ino->number);
                if (!level) {
                    for (size_t j = 0; j < count; ++j)
                        extent_encode(p + 72 + j * 16, map->ext + consumed + j);
                    keys[base + i] = map->ext[consumed].logical;
                } else {
                    for (size_t j = 0; j < count; ++j) {
                        w64(p + 72 + j * 8, keys[prevbase + consumed + j]);
                        w64(p + 72 + leafcap * 8 + j * 8, map->nodes[prevbase + consumed + j]);
                    }
                    keys[base + i] = keys[prevbase + consumed];
                }
                crc_set(p, 4096, 64);
                consumed += count;
            }
            prevbase = base;
            prevcount = shape[level];
            base += shape[level];
        }
        if (!r) {
            uint8_t* p = ino->bytes + 176;
            w16(p, height);
            w16(p + 2, prevcount);
            for (size_t i = 0; i < prevcount; ++i) {
                w64(p + 4 + i * 8, keys[prevbase + i]);
                w64(p + 4 + rootcap * 8 + i * 8, map->nodes[prevbase + i]);
            }
        }
        kfree(keys);
        if (r)
            return r;
    }
    return inode_store(m, ino);
}
static int map_destroy(struct xfs_mount* m, struct xw_map* map) {
    int r = map_trim(m, map, 0);
    for (size_t i = 0; !r && i < map->nnodes; ++i)
        r = block_release(m, map->nodes[i], 1);
    map->nnodes = 0;
    return r;
}
static int new_block(struct xfs_mount* m, struct xfs_inode* ino, struct xw_map* map, uint64_t logical, unsigned type,
                     uint8_t** p, uint64_t* physical) {
    uint64_t fsb;
    int r = block_allocate(m, 1, 1, ino->number >> (m->aglog + 3), &fsb);
    if (!r)
        r = block_offset(m, fsb, physical);
    if (!r)
        r = map_set(m, map, logical, fsb);
    if (r)
        return r;
    *p = edit_buffer(m, *physical, 4096, type);
    if (!*p)
        return m->transaction->error;
    memset(*p, 0, 4096);
    return 0;
}
static int write_inode_data(struct xfs_mount* m, struct xfs_inode* ino, uint64_t offset, const void* buf,
                            size_t count) {
    struct xw_map map;
    int r = map_load(m, ino, &map);
    if (r)
        return r;
    size_t done = 0;
    while (!r && done < count) {
        uint64_t logical = (offset + done) / 4096, fsb, physical;
        bool unwritten = false;
        size_t within = (offset + done) % 4096, take = 4096 - within;
        if (take > count - done)
            take = count - done;
        uint8_t* p = NULL;
        if (map_get(&map, logical, &fsb, &unwritten)) {
            r = block_offset(m, fsb, &physical);
            if (!r && !(p = edit_buffer(m, physical, 4096, 0)))
                r = m->transaction->error;
            if (!r && unwritten) {
                memset(p, 0, 4096);
                r = map_set(m, &map, logical, fsb);
            }
        } else
            r = new_block(m, ino, &map, logical, 0, &p, &physical);
        if (!r) {
            memcpy(p + within, (const uint8_t*)buf + done, take);
            done += take;
        }
    }
    if (!r) {
        if (offset + count > ino->size)
            ino->size = offset + count;
        stamp_time(ino->bytes + 40);
        r = map_store(m, ino, &map);
    }
    map_dispose(&map);
    return r;
}
static int truncate_inode(struct xfs_mount* m, struct xfs_inode* ino, uint64_t size) {
    struct xw_map map;
    int r = map_load(m, ino, &map);
    if (r)
        return r;
    if (size < ino->size) {
        r = map_trim(m, &map, (size + 4095) / 4096);
        uint64_t old;
        bool unwritten;
        if (!r && size % 4096 && map_get(&map, size / 4096, &old, &unwritten) && !unwritten) {
            uint8_t* data = kmalloc(4096);
            if (!data)
                r = -ENOMEM;
            uint64_t off;
            if (!r)
                r = block_offset(m, old, &off);
            if (!r)
                r = disk_read(m, off, data, 4096);
            uint8_t* p;
            if (!r)
                r = new_block(m, ino, &map, size / 4096, 0, &p, &off);
            if (!r) {
                memcpy(p, data, size % 4096);
                r = block_release(m, old, 1);
            }
            kfree(data);
        }
    }
    if (!r) {
        ino->size = size;
        stamp_time(ino->bytes + 40);
        r = map_store(m, ino, &map);
    }
    map_dispose(&map);
    return r;
}
