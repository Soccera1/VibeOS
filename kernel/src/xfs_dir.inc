struct xw_name {
    uint64_t ino;
    uint8_t type;
    char name[FS_MAX_NAME];
};
struct xw_dir {
    struct xw_name* names;
    size_t count, cap;
    uint64_t parent;
    struct xfs_mount* mount;
};
static uint8_t xfs_type(uint32_t mode) {
    switch (mode & FS_S_IFMT) {
    case FS_S_IFREG:
        return 1;
    case FS_S_IFDIR:
        return 2;
    case FS_S_IFCHR:
        return 3;
    case FS_S_IFBLK:
        return 4;
    case FS_S_IFIFO:
        return 5;
    case FS_S_IFSOCK:
        return 6;
    case FS_S_IFLNK:
        return 7;
    default:
        return 0;
    }
}
static int dir_add(struct xw_dir* d, const char* name, uint64_t ino, uint8_t type) {
    if (!name || !*name || strlen(name) >= FS_MAX_NAME || !strcmp(name, ".") || !strcmp(name, ".."))
        return -EINVAL;
    for (size_t i = 0; i < d->count; ++i)
        if (!strcmp(d->names[i].name, name))
            return -EEXIST;
    int r = vector_grow((void**)&d->names, &d->cap, d->count + 1, sizeof(*d->names));
    if (r)
        return r;
    struct xw_name* n = d->names + d->count++;
    n->ino = ino;
    n->type = type;
    strcpy(n->name, name);
    return 0;
}
static int dir_read_name(const uint8_t* name, size_t len, uint64_t ino, void* ctx) {
    struct xw_dir* d = ctx;
    if (len == 1 && name[0] == '.')
        return 0;
    if (len == 2 && name[0] == '.' && name[1] == '.') {
        d->parent = ino;
        return 0;
    }
    if (len >= FS_MAX_NAME)
        return -ENAMETOOLONG;
    char s[FS_MAX_NAME];
    memcpy(s, name, len);
    s[len] = 0;
    struct xfs_inode child;
    int r = inode_read(d->mount, ino, &child);
    return r ? r : dir_add(d, s, ino, xfs_type(child.mode));
}
static int dir_load(struct xfs_mount* m, struct xfs_inode* ino, struct xw_dir* d) {
    memset(d, 0, sizeof(*d));
    d->mount = m;
    if (ino->format == 1 && ino->size >= 6)
        d->parent = ino->bytes[177] ? be64(ino->bytes + 178) : be32(ino->bytes + 178);
    int r = directory_walk(m, ino, dir_read_name, d);
    if (!r && !d->parent)
        r = -EIO;
    if (r) {
        kfree(d->names);
        d->names = NULL;
    }
    return r;
}
static int dir_find(struct xw_dir* d, const char* name) {
    for (size_t i = 0; i < d->count; ++i)
        if (!strcmp(d->names[i].name, name))
            return (int)i;
    return -ENOENT;
}
static void dir_remove(struct xw_dir* d, size_t i) {
    memmove(d->names + i, d->names + i + 1, (d->count - i - 1) * sizeof(*d->names));
    --d->count;
}
static uint32_t name_hash(const char* name) {
    uint32_t hash = 0;
    while (*name)
        hash = (hash << 7 | hash >> 25) ^ (uint8_t)*name++;
    return hash;
}
static void dir_header(struct xfs_mount* m, struct xfs_inode* ino, uint8_t* p, uint64_t physical, uint32_t magic) {
    w32(p, magic);
    w64(p + 8, physical / 512);
    memcpy(p + 24, m->uuid, 16);
    w64(p + 40, ino->number);
}
static void da_header(struct xfs_mount* m, struct xfs_inode* ino, uint8_t* p, uint64_t physical, uint16_t magic,
                      unsigned count) {
    w16(p + 8, magic);
    w64(p + 16, physical / 512);
    memcpy(p + 32, m->uuid, 16);
    w64(p + 48, ino->number);
    w16(p + 56, count);
}
static size_t dir_entry_size(const char* name) {
    return (12 + strlen(name) + 7) & ~(size_t)7;
}
static void dir_data_entry(uint8_t* p, size_t at, const struct xw_name* n) {
    size_t len = strlen(n->name), bytes = dir_entry_size(n->name);
    w64(p + at, n->ino);
    p[at + 8] = len;
    memcpy(p + at + 9, n->name, len);
    p[at + 9 + len] = n->type;
    w16(p + at + bytes - 2, at);
}
static void dir_free_tail(uint8_t* p, size_t start, size_t end) {
    if (end > start) {
        w16(p + start, 0xffff);
        w16(p + start + 2, end - start);
        w16(p + end - 2, start);
        w16(p + 48, start);
        w16(p + 50, end - start);
    }
}
static int dir_store(struct xfs_mount* m, struct xfs_inode* ino, struct xw_dir* d) {
    if ((ino->mode & FS_S_IFMT) != FS_S_IFDIR || be32(ino->bytes + 16) < 2)
        return -EIO;
    stamp_time(ino->bytes + 40);
    struct xw_map map;
    int r = map_load(m, ino, &map);
    if (r)
        return r;
    r = map_destroy(m, &map);
    if (r) {
        map_dispose(&map);
        return r;
    }
    size_t wide = d->parent > UINT32_MAX, data_size = 96;
    for (size_t i = 0; i < d->count; ++i) {
        wide += d->names[i].ino > UINT32_MAX;
        data_size += dir_entry_size(d->names[i].name);
    }
    size_t width = wide ? 8 : 4, sfsize = 2 + width;
    for (size_t i = 0; i < d->count; ++i)
        sfsize += 4 + strlen(d->names[i].name) + width;
    if (sfsize <= ino->fork && d->count <= 255 && wide <= 255 && data_size <= UINT16_MAX) {
        uint8_t* p = ino->bytes + 176;
        memset(p, 0, ino->fork);
        p[0] = d->count;
        p[1] = wide;
        if (width == 8)
            w64(p + 2, d->parent);
        else
            w32(p + 2, d->parent);
        size_t pos = 2 + width, offset = 96;
        for (size_t i = 0; i < d->count; ++i) {
            struct xw_name* n = d->names + i;
            size_t len = strlen(n->name);
            p[pos] = len;
            w16(p + pos + 1, offset);
            memcpy(p + pos + 3, n->name, len);
            p[pos + 3 + len] = n->type;
            if (width == 8)
                w64(p + pos + 4 + len, n->ino);
            else
                w32(p + pos + 4 + len, n->ino);
            pos += 4 + len + width;
            offset += dir_entry_size(n->name);
        }
        ino->format = 1;
        ino->size = sfsize;
        ino->extents = 0;
        w64(ino->bytes + 64, 0);
        r = inode_store(m, ino);
        map_dispose(&map);
        return r;
    }
    size_t nentries = d->count + 2;
    uint8_t* hashes = kmalloc(nentries * 8);
    uint16_t* bests = kmalloc(nentries * sizeof(uint16_t));
    if (!hashes || !bests) {
        kfree(hashes);
        kfree(bests);
        map_dispose(&map);
        return -ENOMEM;
    }
    bool combined = data_size + 8 + nentries * 8 <= 4096;
    size_t db = 0, pos = 64, limit = combined ? 4096 - 8 - nentries * 8 : 4096;
    uint8_t* p = NULL;
    uint64_t physical;
    r = new_block(m, ino, &map, 0, combined ? 10 : 11, &p, &physical);
    if (!r)
        dir_header(m, ino, p, physical, combined ? 0x58444233 : 0x58444433);
    for (size_t i = 0; i < nentries && !r; ++i) {
        struct xw_name special = {.ino = i ? d->parent : ino->number, .type = 2, .name = "."};
        if (i == 1)
            strcpy(special.name, "..");
        const struct xw_name* n = i < 2 ? &special : d->names + i - 2;
        size_t bytes = dir_entry_size(n->name);
        if (pos + bytes > limit) {
            dir_free_tail(p, pos, limit);
            bests[db] = limit - pos;
            crc_set(p, 4096, 4);
            ++db;
            pos = 64;
            r = new_block(m, ino, &map, db, 11, &p, &physical);
            if (r)
                break;
            dir_header(m, ino, p, physical, 0x58444433);
        }
        dir_data_entry(p, pos, n);
        w32(hashes + i * 8, name_hash(n->name));
        w32(hashes + i * 8 + 4, (db * 4096 + pos) / 8);
        pos += bytes;
    }
    if (!r) {
        dir_free_tail(p, pos, limit);
        bests[db] = limit - pos;
        for (size_t i = 1; i < nentries; ++i) {
            uint8_t temp[8];
            memcpy(temp, hashes + i * 8, 8);
            size_t j = i;
            while (j && be32(hashes + (j - 1) * 8) > be32(temp)) {
                memcpy(hashes + j * 8, hashes + (j - 1) * 8, 8);
                --j;
            }
            memcpy(hashes + j * 8, temp, 8);
        }
        if (combined) {
            memcpy(p + limit, hashes, nentries * 8);
            w32(p + 4088, nentries);
        }
        crc_set(p, 4096, 4);
    }
    const uint64_t leafbase = 1ull << 23, freebase = 1ull << 24;
    size_t dbcount = db + 1;
    if (!r && !combined && 64 + nentries * 8 + dbcount * 2 + 4 <= 4096) {
        r = new_block(m, ino, &map, leafbase, 13, &p, &physical);
        if (!r) {
            da_header(m, ino, p, physical, 0x3df1, nentries);
            memcpy(p + 64, hashes, nentries * 8);
            w32(p + 4092, dbcount);
            for (size_t i = 0; i < dbcount; ++i)
                w16(p + 4092 - dbcount * 2 + i * 2, bests[i]);
            crc_set(p, 4096, 12);
        }
    } else if (!r && !combined) {
        size_t leaves = (nentries + 503) / 504;
        if (leaves > 504)
            r = -EFBIG;
        uint8_t* root = NULL;
        if (!r)
            r = new_block(m, ino, &map, leafbase, 15, &root, &physical);
        if (!r) {
            da_header(m, ino, root, physical, 0x3ebe, leaves);
            w16(root + 58, 1);
        }
        size_t consumed = 0;
        for (size_t i = 0; !r && i < leaves; ++i) {
            size_t count = nentries / leaves + (i < nentries % leaves);
            r = new_block(m, ino, &map, leafbase + i + 1, 14, &p, &physical);
            if (r)
                break;
            da_header(m, ino, p, physical, 0x3dff, count);
            w32(p, i + 1 < leaves ? leafbase + i + 2 : 0);
            w32(p + 4, i ? leafbase + i : 0);
            memcpy(p + 64, hashes + consumed * 8, count * 8);
            crc_set(p, 4096, 12);
            w32(root + 64 + i * 8, be32(hashes + (consumed + count - 1) * 8));
            w32(root + 68 + i * 8, leafbase + i + 1);
            consumed += count;
        }
        if (!r)
            crc_set(root, 4096, 12);
        for (size_t first = 0; !r && first < dbcount; first += 2016) {
            size_t count = dbcount - first;
            if (count > 2016)
                count = 2016;
            r = new_block(m, ino, &map, freebase + first / 2016, 12, &p, &physical);
            if (r)
                break;
            dir_header(m, ino, p, physical, 0x58444633);
            w32(p + 48, first);
            w32(p + 52, count);
            w32(p + 56, count);
            for (size_t j = 0; j < count; ++j)
                w16(p + 64 + j * 2, bests[first + j]);
            crc_set(p, 4096, 4);
        }
    }
    if (!r) {
        ino->size = dbcount * 4096;
        r = map_store(m, ino, &map);
    }
    kfree(hashes);
    kfree(bests);
    map_dispose(&map);
    return r;
}
static int parent_lookup(struct xfs_mount* m, const char* path, struct xfs_inode* parent, char name[FS_MAX_NAME]) {
    if (!path || strlen(path) >= FS_MAX_PATH)
        return -ENAMETOOLONG;
    size_t len = strlen(path), base = len;
    if (!len || path[len - 1] == '/')
        return -EINVAL;
    while (base && path[base - 1] != '/')
        --base;
    if (!base || len - base >= FS_MAX_NAME || !strcmp(path + base, ".") || !strcmp(path + base, ".."))
        return -EINVAL;
    char parentpath[FS_MAX_PATH];
    memcpy(parentpath, path, base - 1);
    parentpath[base - 1] = 0;
    if (mount_for(parentpath) != m)
        return -EBUSY;
    strcpy(name, path + base);
    struct fs_entry e;
    int r = xfs_lookup(parentpath, &e);
    return r ? r : inode_read(m, e.inode, parent);
}
