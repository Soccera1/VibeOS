/* Focused corrupt-metadata, hole, and extent-tree cases that mkfs prototypes
 * cannot express. Real mkfs compatibility is covered by xfs-host-test.c. */
#include <stdio.h>
#include <stdlib.h>
#include "../kernel/src/xfs.c"

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)
void* kmalloc(size_t n) { return malloc(n); }
void kfree(void* p) { free(p); }
int fs_read(const struct fs_entry* e, size_t off, void* p, size_t n) {
    (void)e; (void)off; (void)p; (void)n;
    CHECK(false); return -1;
}
uint8_t fs_mode_to_dtype(uint32_t mode) { return (mode & FS_S_IFMT) >> 12; }
static uint8_t disk[64 * 4096];
static unsigned io_count;
static uint64_t high_inode_offset;
static int read_test(void* ctx, uint64_t off, void* p, size_t n) {
    (void)ctx;
    ++io_count;
    if (high_inode_offset && off == high_inode_offset) off = 4096;
    if (off > sizeof(disk) || n > sizeof(disk)-off) return -1;
    memcpy(p, disk+off, n);
    return 0;
}
static const struct ext2_storage_ops test_ops = {read_test, NULL};
static void put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void put32(uint8_t* p, uint32_t v) { put16(p, v >> 16); put16(p+2, v); }
static void put64(uint8_t* p, uint64_t v) { put32(p, v >> 32); put32(p+4, v); }
static void extent(uint8_t* p, uint64_t logical, uint64_t physical, uint32_t n, bool unwritten) {
    put64(p, (uint64_t)unwritten << 63 | logical << 9 | physical >> 43);
    put64(p+8, physical << 21 | n);
}
static void superblock(void) {
    memset(disk, 0, sizeof(disk));
    put32(disk, 0x58465342); put32(disk+4, 4096); put64(disk+8, 64);
    put64(disk+48, 8); put64(disk+56, 16);
    put32(disk+84, 64); put32(disk+88, 1);
    put16(disk+100, 0x2004); put16(disk+102, 512); put16(disk+104, 256); put16(disk+106, 16);
    disk[120] = 12; disk[121] = 9; disk[122] = 8; disk[123] = 4; disk[124] = 6;
    uint8_t* root = disk+4096;
    put16(root, 0x494e); put16(root+2, FS_S_IFDIR | 0755); root[4] = 2; root[5] = 1;
    put64(root+56, 6); put32(root+102, 16);
}
int main(void) {
    superblock();
#ifndef CONFIG_KERNEL_XFS
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), true) == -19);
    CHECK(io_count == 0);
    puts("XFS disabled checks passed");
    return 0;
#endif
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), false) == -30);
    CHECK(io_count == 0);
    CHECK(xfs_mount_storage_at("/xfs/nested", &test_ops, NULL, sizeof(disk), true) == -22);
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, 128, true) == -5);
    disk[124] = 64;
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), true) == -22);
    CHECK(!xfs_owns_path("/xfs"));
    superblock(); disk[126] = 1;
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), true) == -22);
    superblock(); put16(disk+100, 0x2005); put32(disk+216, 16);
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), true) == -95);
    superblock(); put16(disk+100, 0x2005);
    CHECK(xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), true) == -5); /* bad CRC */
    superblock();
    CHECK(!xfs_mount_storage_at("/xfs", &test_ops, NULL, sizeof(disk), true));
    CHECK(xfs_owns_path("/xfs") && !xfs_owns_path("/xfs-other"));
    struct fs_entry entry;
    CHECK(!xfs_lookup("/xfs", &entry));
    struct xfs_mount* m = mount_for("/xfs");
    struct xfs_inode ino = {.number=17, .size=5*4096, .core=100, .fork=156, .mode=FS_S_IFREG|0644, .format=2, .extents=2};
    extent(ino.bytes+100, 1, 4, 1, false);
    extent(ino.bytes+116, 3, 5, 1, true);
    memset(disk+4*4096, 'x', 4096); memset(disk+5*4096, 'z', 4096);
    uint8_t buf[5*4096];
    CHECK(data_read(m, &ino, 0, buf, sizeof(buf)) == sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i) CHECK(buf[i] == (i >= 4096 && i < 8192 ? 'x' : 0));
    extent(ino.bytes+100, 0, 63, 2, false);
    CHECK(data_read(m, &ino, 0, buf, 1) == -5); /* extent crosses AG */
    extent(ino.bytes+100, 0, 4, 0, false);
    CHECK(data_read(m, &ino, 0, buf, 1) == -5);
    /* Two-level extent tree: inode root -> internal block -> leaf. */
    ino.format = 3; ino.extents = 10;
    memset(ino.bytes, 0, sizeof(ino.bytes));
    put16(ino.bytes+100, 2); put16(ino.bytes+102, 1);
    put64(ino.bytes+104+((ino.fork-4)/16)*8, 6);
    uint8_t* node = disk+6*4096;
    put32(node, 0x424d4150); put16(node+4, 1); put16(node+6, 1);
    put64(node+24+((4096-24)/16)*8, 7);
    uint8_t* leaf = disk+7*4096;
    put32(leaf, 0x424d4150); put16(leaf+6, 1);
    extent(leaf+24, 1, 4, 1, false);
    CHECK(data_read(m, &ino, 4096-1, buf, 3) == 3);
    CHECK(buf[0] == 0 && buf[1] == 'x' && buf[2] == 'x');
    put64(node+24+((4096-24)/16)*8, 6); /* cycle cannot hang */
    CHECK(data_read(m, &ino, 4096, buf, 1) == -5);
    put16(ino.bytes+100, 9);
    CHECK(data_read(m, &ino, 0, buf, 1) == -5);
    /* Full-width inode numbers and non-power-of-two AG addressing. */
    m->aglog = 10; m->agblocks = 1000; m->agcount = 262146;
    m->blocks = (uint64_t)m->agblocks*m->agcount; m->size = m->blocks*4096;
    uint64_t number = (262145ull << 14) | 16;
    high_inode_offset = (262145ull*1000+1)*4096;
    CHECK(!inode_read(m, number, &ino));
    CHECK(ino.number == number && ino.number > UINT32_MAX);
    uint64_t off;
    CHECK(block_offset(m, (262145ull << 10) | 1001, &off) == -5);
    puts("XFS malformed metadata and extent checks passed");
    return 0;
}
