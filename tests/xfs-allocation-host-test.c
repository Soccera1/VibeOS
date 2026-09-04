/* Build valid extreme allocation states without thousands of namespace
 * operations, then exercise the same allocator, transaction and VFS paths. */
#include "../kernel/src/xfs.c"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define CHECK(e)                                                                                                       \
    do {                                                                                                               \
        if (!(e)) {                                                                                                    \
            fprintf(stderr, "line %d: %s\n", __LINE__, #e);                                                            \
            exit(1);                                                                                                   \
        }                                                                                                              \
    } while (0)
void* kmalloc(size_t n) { return malloc(n); }
void kfree(void* p) { free(p); }
int fs_read(const struct fs_entry* e, size_t o, void* p, size_t n) {
    (void)e;
    (void)o;
    (void)p;
    (void)n;
    return -1;
}
uint8_t fs_mode_to_dtype(uint32_t mode) { return (mode & FS_S_IFMT) >> 12; }
static int rd(void* c, uint64_t o, void* p, size_t n) { return pread(*(int*)c, p, n, o) == (ssize_t)n ? 0 : -1; }
static int wr(void* c, uint64_t o, const void* p, size_t n) { return pwrite(*(int*)c, p, n, o) == (ssize_t)n ? 0 : -1; }
static int fl(void* c) {
    (void)c;
    return 0;
}
int main(int argc, char** argv) {
    CHECK(argc == 3);
    int fd = open(argv[1], O_RDWR);
    CHECK(fd >= 0);
    const struct ext2_storage_ops ops = {rd, wr, fl};
    CHECK(!xfs_mount_storage_at("/xfs", &ops, &fd, lseek(fd, 0, SEEK_END), false));
    struct xfs_mount* m = mount_for("/xfs");
    struct fs_entry e;
    if (!strcmp(argv[2], "pad-log")) {
        uint8_t* record = kmalloc(512 + 32768);
        CHECK(record);
        uint32_t target = m->logbytes / 512 - 4;
        CHECK((uint32_t)m->lognext < target);
        while ((uint32_t)m->lognext < target) {
            size_t remaining = target - (uint32_t)m->lognext;
            size_t sectors = remaining > 65 ? 65 : remaining;
            if (remaining - sectors == 1)
                --sectors;
            CHECK(sectors >= 2);
            memset(record, 0, 512 + 32768);
            uint8_t unmount[8] = {0x6e, 0x55};
            log_op(record + 512, 0, 0x20, unmount, 8);
            CHECK(!log_emit(m, record, (sectors - 1) * 512, 1, m->lognext));
        }
        kfree(record);
        CHECK(!close(fd));
        return 0;
    }
    if (!strcmp(argv[2], "shrink")) {
        CHECK(!xfs_lookup("/xfs/extremes", &e));
        CHECK(!xfs_truncate(&e, 0));
        CHECK(xfs_write(&e, 0, "reused", 6) == 6);
    } else {
        CHECK(!xfs_create("/xfs/extremes", 0644, 0, 0, &e));
        CHECK(!transaction_begin(m));
        struct xfs_inode ino;
        CHECK(!inode_read(m, e.inode, &ino));
        struct xw_map map = {0};
        uint64_t fsb;
        if (!strcmp(argv[2], "grow")) {
            CHECK(!block_allocate(m, 1400, 1, 0, &fsb));
            for (unsigned i = 0; i < 1400; ++i) {
                if (i & 1)
                    CHECK(!block_release(m, fsb + i, 1));
                else
                    CHECK(!map_append(&map, (struct xw_extent){i, fsb + i, 1, true}));
            }
            ino.size = 1400 * 4096;
        } else {
            uint64_t logical = 0;
            for (unsigned amount = 1024; amount; amount = amount == 1024 ? 1 : 0) {
                int r;
                while (!(r = block_allocate(m, amount, 1, -1, &fsb))) {
                    CHECK(!map_append(&map, (struct xw_extent){logical, fsb, amount, true}));
                    logical += amount;
                }
                CHECK(r == -ENOSPC);
            }
            map_merge(m, &map);
            ino.size = logical * 4096;
        }
        CHECK(!map_store(m, &ino, &map));
        map_dispose(&map);
        CHECK(!finish_mutation(m, 0));
        CHECK(!xfs_lookup("/xfs/extremes", &e));
        char data[16];
        CHECK(xfs_read(&e, 0, data, sizeof(data)) == sizeof(data));
        for (size_t i = 0; i < sizeof(data); ++i)
            CHECK(data[i] == 0);
        if (!strcmp(argv[2], "full"))
            CHECK(xfs_write(&e, e.size, "x", 1) == -ENOSPC);
    }
    CHECK(!xfs_sync_all());
    CHECK(!close(fd));
    puts("XFS allocation checks passed");
    return 0;
}
