static int finish_mutation(struct xfs_mount* m, int r) {
    if (r) {
        transaction_discard(m);
        return r;
    }
    return transaction_commit(m);
}
static int symlink_inode(struct xfs_mount* m, struct xfs_inode* ino, const char* target) {
    ino->size = strlen(target);
    if (ino->size <= ino->fork) {
        ino->format = 1;
        memcpy(ino->bytes + 176, target, ino->size);
        return inode_store(m, ino);
    }
    struct xw_map map = {0};
    uint64_t off;
    uint8_t* p;
    int r = new_block(m, ino, &map, 0, 9, &p, &off);
    if (!r) {
        w32(p, 0x58534c4d);
        w32(p + 8, ino->size);
        memcpy(p + 16, m->uuid, 16);
        w64(p + 32, ino->number);
        w64(p + 40, off / 512);
        memcpy(p + 56, target, ino->size);
        crc_set(p, 4096, 12);
        r = map_store(m, ino, &map);
    }
    map_dispose(&map);
    return r;
}
static int create_node(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, uint32_t rdev, const char* target,
                       struct fs_entry* out) {
    struct xfs_mount* m = mount_for(path);
    int r = transaction_begin(m);
    if (r)
        return r;
    struct xfs_inode parent, ino;
    char name[FS_MAX_NAME];
    struct xw_dir dir = {0};
    r = parent_lookup(m, path, &parent, name);
    if (!r)
        r = dir_load(m, &parent, &dir);
    if (!r && dir_find(&dir, name) >= 0)
        r = -EEXIST;
    if (!r && (parent.mode & 02000)) {
        gid = be32(parent.bytes + 12);
        if ((mode & FS_S_IFMT) == FS_S_IFDIR)
            mode |= 02000;
    }
    if (!r)
        r = inode_allocate(m, mode, uid, gid, &ino);
    if (!r) {
        switch (mode & FS_S_IFMT) {
        case FS_S_IFDIR: {
            if (be32(parent.bytes + 16) >= INT32_MAX) {
                r = -EMLINK;
                break;
            }
            struct xw_dir empty = {.parent = parent.number};
            w32(ino.bytes + 16, 2);
            w32(parent.bytes + 16, be32(parent.bytes + 16) + 1);
            r = dir_store(m, &ino, &empty);
            break;
        }
        case FS_S_IFLNK:
            r = symlink_inode(m, &ino, target);
            break;
        case FS_S_IFREG:
            r = inode_store(m, &ino);
            break;
        default:
            ino.format = 0;
            w32(ino.bytes + 176, rdev);
            r = inode_store(m, &ino);
            break;
        }
    }
    if (!r)
        r = dir_add(&dir, name, ino.number, xfs_type(mode));
    if (!r)
        r = dir_store(m, &parent, &dir);
    kfree(dir.names);
    r = finish_mutation(m, r);
    return r ? r : xfs_lookup(path, out);
}
int xfs_create(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    return create_node(path, FS_S_IFREG | (mode & 07777), uid, gid, 0, NULL, out);
}
int xfs_mkdir(const char* path, uint32_t mode, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    return create_node(path, FS_S_IFDIR | (mode & 07777), uid, gid, 0, NULL, out);
}
int xfs_mknod(const char* path, uint32_t mode, uint32_t rdev, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    uint32_t type = mode & FS_S_IFMT;
    if (type != FS_S_IFREG && type != FS_S_IFIFO && type != FS_S_IFCHR && type != FS_S_IFBLK && type != FS_S_IFSOCK)
        return -EINVAL;
    uint32_t major = (rdev >> 8) & 0xfff, minor = (rdev & 255) | ((rdev >> 12) & 0xfff00);
    if ((type == FS_S_IFCHR || type == FS_S_IFBLK) && minor > 0x3ffff)
        return -EINVAL;
    rdev = (type == FS_S_IFCHR || type == FS_S_IFBLK) ? (major << 18) | minor : 0;
    return create_node(path, mode, uid, gid, rdev, NULL, out);
}
int xfs_symlink(const char* target, const char* path, uint32_t uid, uint32_t gid, struct fs_entry* out) {
    if (!target || !*target)
        return -EINVAL;
    if (strlen(target) > 1024)
        return -ENAMETOOLONG;
    return create_node(path, FS_S_IFLNK | 0777, uid, gid, 0, target, out);
}
int xfs_write(struct fs_entry* entry, size_t offset, const void* buf, size_t count) {
    if (!entry || (!buf && count) || entry->backend != FS_BACKEND_XFS || count > INT32_MAX)
        return -EINVAL;
    struct xfs_mount* m = mount_for(entry->path);
    if (!m || !m->writable || entry->read_only)
        return -EROFS;
    if (offset > INT64_MAX || count > INT64_MAX - offset)
        return -EFBIG;
    size_t done = 0;
    while (done < count) {
        int r = transaction_begin(m);
        if (r)
            return done ? (int)done : r;
        struct xfs_inode ino;
        r = inode_read(m, entry->inode, &ino);
        if (!r && (ino.mode & FS_S_IFMT) != FS_S_IFREG)
            r = -EISDIR;
        size_t n = count - done;
        if (n > 65536)
            n = 65536;
        if (!r)
            r = write_inode_data(m, &ino, offset + done, (const uint8_t*)buf + done, n);
        r = finish_mutation(m, r);
        if (r)
            return done ? (int)done : r;
        entry->size = ino.size;
        done += n;
    }
    return (int)done;
}
int xfs_truncate(struct fs_entry* entry, size_t size) {
    if (!entry || entry->backend != FS_BACKEND_XFS)
        return -EINVAL;
    if (entry->read_only)
        return -EROFS;
    if (size > INT64_MAX)
        return -EFBIG;
    struct xfs_mount* m = mount_for(entry->path);
    int r = transaction_begin(m);
    if (r)
        return r;
    struct xfs_inode ino;
    r = inode_read(m, entry->inode, &ino);
    if (!r && (ino.mode & FS_S_IFMT) != FS_S_IFREG)
        r = -EISDIR;
    if (!r)
        r = truncate_inode(m, &ino, size);
    r = finish_mutation(m, r);
    if (!r)
        entry->size = size;
    return r;
}
static bool (*inode_busy)(const char*, uint64_t);
void xfs_set_inode_busy_checker(bool (*checker)(const char*, uint64_t)) { inode_busy = checker; }
static int orphan_add(struct xfs_mount* m, struct xfs_inode* ino) {
    m->has_orphans = true;
    struct xw_ag* a = ag_load(m, ino->number >> (m->aglog + 3));
    if (!a)
        return m->transaction->error;
    uint32_t agino = ino->number & ((1ull << (m->aglog + 3)) - 1);
    uint8_t* bucket = a->agi + 40 + (agino % 64) * 4;
    w32(ino->bytes + 96, be32(bucket));
    w32(bucket, agino);
    return inode_store(m, ino);
}
static int destroy_inode(struct xfs_mount* m, struct xfs_inode* ino) {
    struct xw_map map;
    int r = map_load(m, ino, &map);
    if (r)
        return r;
    r = map_destroy(m, &map);
    map_dispose(&map);
    return r ? r : inode_release(m, ino);
}
static int drop_link(struct xfs_mount* m, struct xfs_inode* ino, bool directory) {
    uint32_t links = be32(ino->bytes + 16);
    if (!links)
        return -EIO;
    links = directory ? 0 : links - 1;
    w32(ino->bytes + 16, links);
    if (links)
        return inode_store(m, ino);
    if (inode_busy && inode_busy(m->path, ino->number))
        return orphan_add(m, ino);
    return destroy_inode(m, ino);
}
static int reap_mount(struct xfs_mount* m) {
    if (!m->writable)
        return 0;
    if (m->failed)
        return -EIO;
    if (!m->has_orphans)
        return 0;
    bool remaining = false;
    /* One orphan per transaction bounds recovery memory and journal usage. */
    for (uint32_t ag = 0; ag < m->agcount; ++ag)
        for (unsigned bucket = 0; bucket < 64; ++bucket) {
            uint64_t agibase = (uint64_t)ag * m->agblocks * 4096 + 1024;
            uint8_t field[4];
            int r = disk_read(m, agibase + 40 + bucket * 4, field, 4);
            if (r)
                return r;
            uint32_t current = be32(field), previous = UINT32_MAX;
            uint64_t visited = 0;
            while (current != UINT32_MAX) {
                if (++visited > (uint64_t)m->agblocks * 8 || current % 64 != bucket)
                    return -EIO;
                uint64_t number = ((uint64_t)ag << (m->aglog + 3)) + current;
                struct xfs_inode ino;
                r = inode_read(m, number, &ino);
                if (r)
                    return r;
                if (be32(ino.bytes + 16))
                    return -EIO;
                uint32_t next = be32(ino.bytes + 96);
                if (!inode_busy || !inode_busy(m->path, number)) {
                    r = transaction_begin(m);
                    if (r)
                        return r;
                    struct xw_ag* a = ag_load(m, ag);
                    if (!a)
                        r = m->transaction->error;
                    if (!r && previous == UINT32_MAX)
                        w32(a->agi + 40 + bucket * 4, next);
                    else if (!r) {
                        struct xfs_inode prev;
                        r = inode_read(m, ((uint64_t)ag << (m->aglog + 3)) + previous, &prev);
                        if (!r) {
                            w32(prev.bytes + 96, next);
                            r = inode_store(m, &prev);
                        }
                    }
                    if (!r)
                        r = destroy_inode(m, &ino);
                    r = finish_mutation(m, r);
                    if (r)
                        return r;
                } else {
                    previous = current;
                    remaining = true;
                }
                current = next;
            }
        }
    m->has_orphans = remaining;
    return 0;
}
int xfs_sync_all(void) {
    for (size_t i = 0; i < XFS_MOUNTS; ++i)
        if (mounts[i].used && mounts[i].writable) {
            int r = reap_mount(&mounts[i]);
            if (!r)
                r = durable(&mounts[i]);
            if (r)
                return r;
        }
    return 0;
}
int xfs_link(const char* existing, const char* path) {
    struct xfs_mount *m = mount_for(existing), *n = mount_for(path);
    if ((m && !m->writable) || (n && !n->writable))
        return -EROFS;
    if (!m || n != m)
        return -EXDEV;
    int r = transaction_begin(m);
    if (r)
        return r;
    struct fs_entry e;
    struct xfs_inode ino, parent;
    struct xw_dir dir = {0};
    char name[FS_MAX_NAME];
    r = xfs_lookup(existing, &e);
    if (!r)
        r = inode_read(m, e.inode, &ino);
    if (!r && (ino.mode & FS_S_IFMT) == FS_S_IFDIR)
        r = -EISDIR;
    if (!r && be32(ino.bytes + 16) >= INT32_MAX)
        r = -EMLINK;
    if (!r)
        r = parent_lookup(m, path, &parent, name);
    if (!r)
        r = dir_load(m, &parent, &dir);
    if (!r)
        r = dir_add(&dir, name, ino.number, xfs_type(ino.mode));
    if (!r) {
        w32(ino.bytes + 16, be32(ino.bytes + 16) + 1);
        r = inode_store(m, &ino);
    }
    if (!r)
        r = dir_store(m, &parent, &dir);
    kfree(dir.names);
    return finish_mutation(m, r);
}
static int remove_node(const char* path, bool directory) {
    struct xfs_mount* m = mount_for(path);
    int r = transaction_begin(m);
    if (r)
        return r;
    struct xfs_inode parent, ino;
    struct xw_dir dir = {0}, child = {0};
    char name[FS_MAX_NAME];
    r = parent_lookup(m, path, &parent, name);
    if (!r)
        r = dir_load(m, &parent, &dir);
    int index = -1;
    if (!r && (index = dir_find(&dir, name)) < 0)
        r = index;
    if (!r)
        r = inode_read(m, dir.names[index].ino, &ino);
    if (!r && ((ino.mode & FS_S_IFMT) == FS_S_IFDIR) != directory)
        r = directory ? -ENOTDIR : -EISDIR;
    if (!r && directory) {
        r = dir_load(m, &ino, &child);
        if (!r && child.count)
            r = -ENOTEMPTY;
    }
    if (!r)
        r = drop_link(m, &ino, directory);
    if (!r) {
        dir_remove(&dir, index);
        if (directory)
            w32(parent.bytes + 16, be32(parent.bytes + 16) - 1);
        r = dir_store(m, &parent, &dir);
    }
    kfree(dir.names);
    kfree(child.names);
    return finish_mutation(m, r);
}
int xfs_unlink(const char* path) { return remove_node(path, false); }
int xfs_rmdir(const char* path) { return remove_node(path, true); }
int xfs_rename(const char* oldpath, const char* newpath) {
    struct xfs_mount *m = mount_for(oldpath), *n = mount_for(newpath);
    if ((m && !m->writable) || (n && !n->writable))
        return -EROFS;
    if (!m || n != m)
        return -EXDEV;
    int r = transaction_begin(m);
    if (r)
        return r;
    struct xfs_inode oldparent, newparent, ino, target;
    char oldname[FS_MAX_NAME], newname[FS_MAX_NAME];
    struct xw_dir olddir = {0}, newdir = {0}, child = {0}, targetdir = {0};
    struct xw_dir* dst = &newdir;
    r = parent_lookup(m, oldpath, &oldparent, oldname);
    if (!r)
        r = parent_lookup(m, newpath, &newparent, newname);
    bool same = !r && oldparent.number == newparent.number;
    if (!r)
        r = dir_load(m, &oldparent, &olddir);
    if (!r) {
        if (same)
            dst = &olddir;
        else
            r = dir_load(m, &newparent, &newdir);
    }
    int src = -1, dest = -1;
    if (!r && (src = dir_find(&olddir, oldname)) < 0)
        r = src;
    if (!r)
        r = inode_read(m, olddir.names[src].ino, &ino);
    if (!r)
        dest = dir_find(dst, newname);
    if (!r && dest >= 0 && dst->names[dest].ino == ino.number) {
        kfree(olddir.names);
        kfree(newdir.names);
        transaction_discard(m);
        return 0;
    }
    bool isdir = !r && (ino.mode & FS_S_IFMT) == FS_S_IFDIR;
    if (!r && isdir) {
        uint64_t ancestor = newparent.number;
        unsigned depth = 0;
        while (!r) {
            if (ancestor == ino.number) {
                r = -EINVAL;
                break;
            }
            if (ancestor == m->root)
                break;
            if (++depth > FS_MAX_PATH) {
                r = -EIO;
                break;
            }
            struct xfs_inode a;
            struct xw_dir d = {0};
            r = inode_read(m, ancestor, &a);
            if (!r)
                r = dir_load(m, &a, &d);
            ancestor = d.parent;
            kfree(d.names);
        }
    }
    if (!r && dest >= 0) {
        r = inode_read(m, dst->names[dest].ino, &target);
        bool target_isdir = !r && (target.mode & FS_S_IFMT) == FS_S_IFDIR;
        if (!r && target_isdir != isdir)
            r = target_isdir ? -EISDIR : -ENOTDIR;
        if (!r && target_isdir) {
            r = dir_load(m, &target, &targetdir);
            if (!r && targetdir.count)
                r = -ENOTEMPTY;
        }
        if (!r)
            r = drop_link(m, &target, target_isdir);
        if (!r) {
            dir_remove(dst, dest);
            if (target_isdir) {
                struct xfs_inode* p = same ? &oldparent : &newparent;
                w32(p->bytes + 16, be32(p->bytes + 16) - 1);
            }
        }
    }
    if (!r) {
        src = dir_find(&olddir, oldname);
        if (src < 0)
            r = -EIO;
        else
            dir_remove(&olddir, src);
    }
    if (!r)
        r = dir_add(dst, newname, ino.number, xfs_type(ino.mode));
    if (!r && isdir && !same) {
        if (be32(newparent.bytes + 16) >= INT32_MAX)
            r = -EMLINK;
        if (!r)
            r = dir_load(m, &ino, &child);
        if (!r) {
            child.parent = newparent.number;
            r = dir_store(m, &ino, &child);
            w32(oldparent.bytes + 16, be32(oldparent.bytes + 16) - 1);
            w32(newparent.bytes + 16, be32(newparent.bytes + 16) + 1);
        }
    }
    if (!r)
        r = dir_store(m, &oldparent, &olddir);
    if (!r && !same)
        r = dir_store(m, &newparent, &newdir);
    kfree(olddir.names);
    kfree(newdir.names);
    kfree(child.names);
    kfree(targetdir.names);
    return finish_mutation(m, r);
}
static int change_metadata(const char* path, const struct fs_entry* entry, unsigned operation, uint32_t a, uint32_t b) {
    struct xfs_mount* m = mount_for(path);
    int r = transaction_begin(m);
    if (r)
        return r;
    struct fs_entry e;
    struct xfs_inode ino;
    if (entry)
        e = *entry;
    else
        r = xfs_lookup(path, &e);
    if (!r)
        r = inode_read(m, e.inode, &ino);
    if (!r && operation == 2 && ((a != FS_UTIME_OMIT && a > INT32_MAX) || (b != FS_UTIME_OMIT && b > INT32_MAX)))
        r = -75;
    if (!r) {
        if (!operation)
            ino.mode = (ino.mode & FS_S_IFMT) | (a & 07777);
        else if (operation == 1) {
            if (a != UINT32_MAX)
                w32(ino.bytes + 8, a);
            if (b != UINT32_MAX)
                w32(ino.bytes + 12, b);
            ino.mode &= ~06000;
        } else {
            if (a != FS_UTIME_OMIT) {
                w32(ino.bytes + 32, a);
                w32(ino.bytes + 36, 0);
            }
            if (b != FS_UTIME_OMIT) {
                w32(ino.bytes + 40, b);
                w32(ino.bytes + 44, 0);
            }
        }
        r = inode_store(m, &ino);
    }
    return finish_mutation(m, r);
}
int xfs_chmod(const char* path, uint32_t mode) { return change_metadata(path, NULL, 0, mode, 0); }
int xfs_chown(const char* path, uint32_t uid, uint32_t gid) { return change_metadata(path, NULL, 1, uid, gid); }
int xfs_utime(const char* path, uint32_t atime, uint32_t mtime) { return change_metadata(path, NULL, 2, atime, mtime); }

int xfs_change_metadata_entry(const struct fs_entry* entry, unsigned operation, uint32_t a, uint32_t b) {
    if (!entry || entry->backend != FS_BACKEND_XFS || operation > 2)
        return -EINVAL;
    return change_metadata(entry->path, entry, operation, a, b);
}
