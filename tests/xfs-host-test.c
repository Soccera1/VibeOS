#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include "fs.h"
#include "xfs.h"

void* kmalloc(size_t n) { return malloc(n); }
void kfree(void* p) { free(p); }
void* krealloc(void* p, size_t n) { return realloc(p, n); }
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)
static size_t image_size;
static unsigned reads, writes;
static int storage_read(void* ctx, uint64_t off, void* buf, size_t n) {
    CHECK(off <= image_size && n <= image_size-off);
    ++reads;
    FILE* f = ctx;
    return fseek(f, (long)off, SEEK_SET) || fread(buf, 1, n, f) != n ? -1 : 0;
}
static int storage_write(void* ctx, uint64_t off, const void* buf, size_t n) {
    (void)ctx; (void)off; (void)buf; (void)n;
    ++writes;
    return -1;
}
static const struct ext2_storage_ops ops = {storage_read, storage_write};
int main(int argc, char** argv) {
    CHECK(argc == 2);
    FILE* f = fopen(argv[1], "rb");
    CHECK(f);
    CHECK(!fseek(f, 0, SEEK_END));
    image_size = ftell(f);
    int r = fs_mount_storage("/usr", &ops, f, image_size, true);
    if (r) fprintf(stderr, "mount result %d\n", r);
    CHECK(r == 0);
    CHECK(fs_mount_ready("/usr"));
    CHECK(!fs_mount_ready("/usrx"));
    CHECK(fs_mount_storage("/usr", &ops, f, image_size, true) == -16);
    CHECK(fs_mount_storage("/home", &ops, f, image_size, false) == -30);
    CHECK(!fs_mount_ready("/home"));
    struct fs_entry e;
    CHECK(!fs_lookup("/usr", &e));
    CHECK((e.mode & FS_S_IFMT) == FS_S_IFDIR);
    CHECK(!fs_lookup("/usr/hello", &e));
    CHECK(e.backend == FS_BACKEND_XFS && e.read_only && e.uid == 1000 && e.gid == 1000);
    char buf[128] = {0};
    CHECK(fs_read(&e, 0, buf, sizeof(buf)) == 15);
    CHECK(!__builtin_memcmp(buf, "hello from XFS\n", 15));
    CHECK(fs_read(&e, 6, buf, 4) == 4 && !__builtin_memcmp(buf, "from", 4));
    CHECK(fs_read(&e, 15, buf, 5) == 0);
    CHECK(fs_read(&e, SIZE_MAX, buf, 5) == 0);
    CHECK(fs_write(&e, 0, buf, 1) == -30);
    CHECK(fs_truncate(&e, 0) == -30);
    CHECK(fs_lookup("/usr/hello/nope", &e) == -20);
    CHECK(fs_lookup("/usr/nope", &e) == -2);
    CHECK(fs_lookup("/usrx/hello", &e) == -2);
    CHECK(!fs_lookup("/usr/sub/nested", &e));
    CHECK(!fs_lookup("/usr/link", &e));
    CHECK(fs_readlink(&e, buf, sizeof(buf)) == 5 && !__builtin_memcmp(buf, "hello", 5));
    CHECK(fs_readlink(&e, buf, 2) == 2 && !__builtin_memcmp(buf, "he", 2));
    CHECK(!fs_lookup("/usr/large", &e));
    CHECK(e.size == 256 * 257);
    for (size_t offset = 0; offset < e.size; offset += sizeof(buf)) {
        int got = fs_read(&e, offset, buf, sizeof(buf));
        CHECK(got == (int)(e.size-offset < sizeof(buf) ? e.size-offset : sizeof(buf)));
        for (int i = 0; i < got; ++i) CHECK((uint8_t)buf[i] == (uint8_t)(offset+i));
    }
    CHECK(!fs_lookup("/usr/remote", &e));
    char target[1024];
    CHECK(fs_readlink(&e, target, sizeof(target)) == 700);
    for (size_t i = 0; i < 700; ++i) CHECK(target[i] == 'a');
    CHECK(fs_readlink(&e, target, 3) == 3);
    CHECK(fs_readlink(&e, target, 0) == 0);
    CHECK(!fs_path_has_child("/usr/empty"));
    CHECK(fs_is_read_only_path("/usr/absent"));
    CHECK(fs_create("/usr/new", 0644, 0, 0, &e) == -30);
    CHECK(fs_mkdir("/usr/newdir", 0755, 0, 0, &e) == -30);
    CHECK(fs_unlink("/usr/hello") == -30);
    CHECK(fs_chmod("/usr/hello", 0600) == -30);
    CHECK(fs_chown("/usr/hello", 0, 0) == -30);
    CHECK(fs_rename("/usr/hello", "/tmp/hello") == -30);
    CHECK(fs_symlink("hello", "/usr/newlink", 0, 0, &e) == -30);
    CHECK(fs_path_has_child("/usr"));
    char names[16][FS_MAX_NAME]; uint8_t types[16];
    size_t n = fs_collect_children("/usr", names, types, 16);
    CHECK(n >= 3);
    bool hello = false, link = false, sub = false;
    for (size_t i = 0; i < n; ++i) {
        if (!__builtin_strcmp(names[i], "hello")) hello = types[i] == FS_DT_REG;
        if (!__builtin_strcmp(names[i], "link")) link = types[i] == FS_DT_LNK;
        if (!__builtin_strcmp(names[i], "sub")) sub = types[i] == FS_DT_DIR;
    }
    CHECK(hello && link && sub);
    CHECK(fs_collect_children("/usr", names, types, 1) == 1);
    CHECK(fs_collect_children("/usr", names, types, 0) == 0);
    CHECK(fs_collect_children("/usr/sub", names, types, 16) == 1);
    CHECK(fs_collect_children("/", names, types, 16) == 1);
    CHECK(!__builtin_strcmp(names[0], "usr"));
    CHECK(reads > 0 && writes == 0);
    uint8_t* image = mmap(NULL, image_size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    CHECK(image != MAP_FAILED);
    CHECK(!fs_mount_image("/image", image, image_size, true));
    CHECK(!fs_lookup("/image/hello", &e));
    CHECK(fs_read(&e, 0, buf, sizeof(buf)) == 15);
    struct fs_entry image_file = {.data=image, .size=image_size, .mode=FS_S_IFREG|0444,
                                  .backend=FS_BACKEND_INITRAMFS, .read_only=true};
    CHECK(!xfs_mount_file_at("/file", &image_file, true));
    CHECK(!fs_lookup("/file/sub/nested", &e));
    CHECK(fs_read(&e, 0, buf, sizeof(buf)) == 15);
    CHECK(!__builtin_memcmp(buf, "hello from XFS\n", 15));
    CHECK(!munmap(image, image_size));
    CHECK(!fclose(f));
    puts("XFS host checks passed");
    return 0;
}
