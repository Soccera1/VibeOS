#include "fs.h"
#include "xfs.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(e)                                                                                                       \
    do {                                                                                                               \
        if (!(e)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #e);                                                    \
            exit(1);                                                                                                   \
        }                                                                                                              \
    } while (0)
void* kmalloc(size_t n) {
    return malloc(n);
}
void kfree(void* p) {
    free(p);
}
void* krealloc(void* p, size_t n) {
    return realloc(p, n);
}
static long fail_after = -1, events;
static bool fail_io, volatile_cache;
struct cached_sector {
    struct cached_sector* next;
    uint64_t off;
    uint8_t data[512];
};
static struct cached_sector* cache;
static void event(void) {
    if (events++ == fail_after && !fail_io)
        _exit(99);
}
static int storage_read(void* c, uint64_t off, void* p, size_t n) {
    if (pread(*(int*)c, p, n, off) != (ssize_t)n)
        return -1;
    for (struct cached_sector* s = cache; s; s = s->next) {
        uint64_t begin = off > s->off ? off : s->off, end = off + n < s->off + 512 ? off + n : s->off + 512;
        if (begin < end)
            memcpy((uint8_t*)p + begin - off, s->data + begin - s->off, end - begin);
    }
    return 0;
}
static int storage_write(void* c, uint64_t off, const void* p, size_t n) {
    for (size_t done = 0; done < n; done += 512) {
        event();
        if (fail_io && events - 1 == fail_after)
            return -1;
        size_t take = n - done < 512 ? n - done : 512;
        if (volatile_cache) {
            CHECK(take == 512 && !(off % 512));
            struct cached_sector* s = cache;
            while (s && s->off != off + done)
                s = s->next;
            if (!s) {
                s = malloc(sizeof(*s));
                CHECK(s);
                s->next = cache;
                cache = s;
                s->off = off + done;
            }
            memcpy(s->data, (const uint8_t*)p + done, 512);
        } else if (pwrite(*(int*)c, (const uint8_t*)p + done, take, off + done) != (ssize_t)take)
            return -1;
    }
    return 0;
}
static int storage_flush(void* c) {
    event();
    if (fail_io && events - 1 == fail_after)
        return -1;
    /* The host file models stable storage; the heap models a volatile device
     * cache. Reverse-order persistence and cuts during flush exercise writes
     * which reach the medium out of submission order. No host power loss is
     * involved, so fsync on the real host device is unnecessary. */
    while (cache) {
        event();
        if (fail_io && events - 1 == fail_after)
            return -1;
        struct cached_sector* s = cache;
        if (pwrite(*(int*)c, s->data, 512, s->off) != 512)
            return -1;
        cache = s->next;
        free(s);
    }
    return 0;
}
static const struct ext2_storage_ops ops = {storage_read, storage_write, storage_flush};
static uint64_t held;
static bool busy(const char* path, uint64_t ino) {
    return !strcmp(path, "/xfs") && ino == held;
}
static void basic(void) {
    struct fs_entry e, alias;
    CHECK(!fs_mkdir("/xfs/a", 0755, 1000, 1000, NULL));
    CHECK(!fs_mkdir("/xfs/b", 0755, 1000, 1000, NULL));
    CHECK(!fs_create("/xfs/a/file", 0644, 1000, 1000, &e));
    CHECK(fs_create("/xfs/a/file", 0644, 1000, 1000, NULL) == -17);
    CHECK(fs_write(&e, 0, "hello", 5) == 5);
    CHECK(fs_write(&e, 1048576, "tail", 4) == 4);
    char buf[32];
    memset(buf, 0xff, sizeof(buf));
    CHECK(fs_read(&e, 4096, buf, sizeof(buf)) == sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i)
        CHECK(!buf[i]);
    CHECK(!fs_truncate(&e, 3));
    CHECK(!fs_truncate(&e, 8192));
    CHECK(fs_read(&e, 0, buf, sizeof(buf)) == sizeof(buf));
    CHECK(!memcmp(buf, "hel", 3));
    for (size_t i = 3; i < sizeof(buf); ++i)
        CHECK(!buf[i]);
    CHECK(!fs_link("/xfs/a/file", "/xfs/a/alias"));
    CHECK(!fs_lookup("/xfs/a/alias", &alias));
    CHECK(alias.inode == e.inode);
    struct xfs_metadata meta;
    CHECK(!xfs_get_metadata(&alias, &meta) && meta.nlink == 2 && meta.blocks == 8);
    CHECK(!fs_rename("/xfs/a/file", "/xfs/b/moved"));
    CHECK(fs_lookup("/xfs/a/file", NULL) == -2);
    CHECK(!fs_chmod("/xfs/b/moved", 0600));
    CHECK(!fs_chown("/xfs/b/moved", 42, 43));
    CHECK(!fs_utime("/xfs/b/moved", 100, 200));
    CHECK(!fs_lookup("/xfs/b/moved", &e));
    CHECK(e.uid == 42 && e.gid == 43 && (e.mode & 0777) == 0600);
    CHECK(!fs_unlink("/xfs/a/alias"));
    CHECK(!fs_symlink("b/moved", "/xfs/short", 0, 0, NULL));
    CHECK(!fs_lookup("/xfs/short", &alias));
    CHECK(fs_readlink(&alias, buf, sizeof(buf)) == 7 && !memcmp(buf, "b/moved", 7));
    char target[701];
    memset(target, 'q', 700);
    target[700] = 0;
    CHECK(!fs_symlink(target, "/xfs/long", 0, 0, &alias));
    char result[701];
    CHECK(fs_readlink(&alias, result, sizeof(result)) == 700 && !memcmp(result, target, 700));
    CHECK(!fs_mkdir("/xfs/a/sub", 0755, 0, 0, NULL));
    CHECK(fs_rename("/xfs/a", "/xfs/a/sub/cycle") == -22);
    CHECK(!fs_rename("/xfs/a/sub", "/xfs/b/sub"));
    CHECK(!fs_rmdir("/xfs/a"));
    CHECK(fs_rmdir("/xfs/b") == -39);
    CHECK(!fs_rmdir("/xfs/b/sub"));
    CHECK(!fs_create("/xfs/b/replacement", 0644, 0, 0, NULL));
    CHECK(!fs_rename("/xfs/b/moved", "/xfs/b/replacement"));
    CHECK(!fs_lookup("/xfs/b/replacement", &e));
    held = e.inode;
    xfs_set_inode_busy_checker(busy);
    CHECK(!fs_unlink("/xfs/b/replacement"));
    CHECK(fs_lookup("/xfs/b/replacement", NULL) == -2);
    CHECK(fs_write(&e, 0, "open", 4) == 4);
    CHECK(!fs_sync());
    CHECK(fs_read(&e, 0, buf, 4) == 4 && !memcmp(buf, "open", 4));
    held = 0;
    CHECK(!fs_sync());
    CHECK(!fs_rmdir("/xfs/b"));
    CHECK(!fs_mknod("/xfs/fifo", FS_S_IFIFO | 0600, 0, 0, 0, &e));
    CHECK((e.mode & FS_S_IFMT) == FS_S_IFIFO);
    CHECK(!fs_unlink("/xfs/fifo"));
    CHECK(!fs_unlink("/xfs/short"));
    CHECK(!fs_unlink("/xfs/long"));
    CHECK(!fs_create("/xfs/persistent", 0644, 1000, 1000, &e));
    CHECK(fs_write(&e, 0, "persistent data", 15) == 15);
}
static void stress(void) {
    CHECK(!fs_mkdir("/xfs/many", 0755, 0, 0, NULL));
    struct fs_entry e;
    for (unsigned i = 0; i < 650; ++i) {
        char path[FS_MAX_PATH];
        snprintf(path, sizeof(path), "/xfs/many/file-%04u-with-a-long-name", i);
        int r = fs_create(path, 0644, 1000, 1000, &e);
        if (r)
            fprintf(stderr, "create %u: %d\n", i, r);
        CHECK(!r);
        CHECK(fs_write(&e, 0, &i, sizeof(i)) == sizeof(i));
    }
    CHECK(!fs_lookup("/xfs/many", &e));
    char names[37][FS_MAX_NAME];
    uint8_t types[37];
    uint64_t numbers[37];
    uint64_t offset = 0;
    int got;
    while ((got = xfs_readdir(&e, offset, names, types, numbers, 37)) > 0) {
        for (int i = 0; i < got; ++i)
            CHECK(numbers[i] != 0);
        offset += got;
    }
    CHECK(got == 0 && offset == 652);
    CHECK(!fs_create("/xfs/fragmented", 0644, 0, 0, &e));
    for (unsigned i = 0; i < 300; ++i)
        CHECK(fs_write(&e, (size_t)i * 8192, &i, sizeof(i)) == sizeof(i));
    for (unsigned i = 0; i < 300; ++i) {
        unsigned n = 0;
        CHECK(fs_read(&e, (size_t)i * 8192, &n, sizeof(n)) == sizeof(n) && n == i);
    }
    CHECK(!fs_truncate(&e, 41));
    for (unsigned i = 0; i < 650; ++i) {
        char path[FS_MAX_PATH];
        snprintf(path, sizeof(path), "/xfs/many/file-%04u-with-a-long-name", i);
        CHECK(!fs_lookup(path, &e));
        unsigned n;
        CHECK(fs_read(&e, 0, &n, sizeof(n)) == sizeof(n) && n == i);
    }
}
static void verify(void) {
    struct fs_entry e;
    char buf[32];
    CHECK(!fs_lookup("/xfs/persistent", &e));
    CHECK(fs_read(&e, 0, buf, sizeof(buf)) == 15 && !memcmp(buf, "persistent data", 15));
}
static void crash_seed(void) {
    CHECK(!fs_mkdir("/xfs/from", 0755, 0, 0, NULL));
    CHECK(!fs_mkdir("/xfs/to", 0755, 0, 0, NULL));
    struct fs_entry e;
    for (unsigned i = 0; i < 80; ++i) {
        char p[FS_MAX_PATH];
        snprintf(p, sizeof(p), "/xfs/from/fill-%03u-with-a-long-name", i);
        CHECK(!fs_create(p, 0644, 0, 0, NULL));
    }
    CHECK(!fs_create("/xfs/from/source", 0644, 0, 0, &e));
    CHECK(fs_write(&e, 0, "source", 6) == 6);
    CHECK(!fs_create("/xfs/to/victim", 0644, 0, 0, &e));
    CHECK(fs_write(&e, 0, "victim", 6) == 6);
}
static void crash_verify(void) {
    struct fs_entry e;
    char buf[8];
    int source = fs_lookup("/xfs/from/source", &e);
    CHECK(source == 0 || source == -2);
    if (!source)
        CHECK(fs_read(&e, 0, buf, 6) == 6 && !memcmp(buf, "source", 6));
    CHECK(!fs_lookup("/xfs/to/victim", &e));
    CHECK(fs_read(&e, 0, buf, 6) == 6 && !memcmp(buf, source ? "source" : "victim", 6));
}
static void remove_stress(void) {
    for (unsigned i = 0; i < 650; ++i) {
        char p[FS_MAX_PATH];
        snprintf(p, sizeof(p), "/xfs/many/file-%04u-with-a-long-name", i);
        CHECK(!fs_unlink(p));
    }
    CHECK(!fs_rmdir("/xfs/many"));
    CHECK(!fs_unlink("/xfs/fragmented"));
}
int main(int argc, char** argv) {
    CHECK(argc == 3);
    if (getenv("XFS_FAIL_AFTER"))
        fail_after = strtol(getenv("XFS_FAIL_AFTER"), NULL, 10);
    fail_io = getenv("XFS_FAIL_IO") != NULL;
    volatile_cache = getenv("XFS_VOLATILE_CACHE") != NULL;
    int fd = open(argv[1], O_RDWR);
    CHECK(fd >= 0);
    off_t size = lseek(fd, 0, SEEK_END);
    CHECK(size > 0);
    int r = fs_mount_storage("/xfs", &ops, &fd, size, false);
    if (r)
        fprintf(stderr, "mount: %d\n", r);
    CHECK(!r);
    if (!strcmp(argv[2], "basic"))
        basic();
    else if (!strcmp(argv[2], "stress"))
        stress();
    else if (!strcmp(argv[2], "remove-stress"))
        remove_stress();
    else if (!strcmp(argv[2], "seed"))
        crash_seed();
    else if (!strcmp(argv[2], "recover"))
        crash_verify();
    else if (!strcmp(argv[2], "rename")) {
        int result = fs_rename("/xfs/from/source", "/xfs/to/victim");
        if (fail_io && events > fail_after) {
            CHECK(result == -5);
            CHECK(fs_sync() == -5);
            close(fd);
            return 98;
        }
        CHECK(!result);
        crash_verify();
    } else
        verify();
    CHECK(!fs_sync());
    CHECK(!close(fd));
    printf("XFS writable host checks passed; events=%ld\n", events);
    return 0;
}
