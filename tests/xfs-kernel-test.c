/* Run only against a disposable XFS disk in the QEMU XFS check. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>
static void done(int ok) {
    puts(ok ? "XFS_KERNEL_WRITE_PASS" : "XFS_KERNEL_WRITE_FAIL");
    fflush(stdout);
    reboot(RB_POWER_OFF);
    _exit(ok ? 0 : 1);
}
#define CHECK(e)                                                                                                       \
    do {                                                                                                               \
        if (!(e)) {                                                                                                    \
            printf("XFS check failed at line %d: %s errno=%d\n", __LINE__, #e, errno);                                 \
            done(0);                                                                                                   \
        }                                                                                                              \
    } while (0)
int main(void) {
    int persisted = open("/home/persistent", O_RDONLY);
    if (persisted >= 0) {
        char buf[32];
        CHECK(read(persisted, buf, sizeof(buf)) == 17 && !memcmp(buf, "kernel-persistent", 17));
        CHECK(!close(persisted));
        puts("XFS_KERNEL_REMOUNT_PASS");
        done(1);
    }
    CHECK(errno == ENOENT);
    CHECK(!mkdir("/home/check", 0755));
    int fd = open("/home/check/file", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "hello", 5) == 5);
    CHECK(pwrite(fd, "tail", 4, 1048576) == 4);
    struct stat st;
    CHECK(!fstat(fd, &st));
    CHECK(st.st_size == 1048580 && st.st_blocks == 16);
    CHECK(!ftruncate(fd, 3));
    CHECK(!ftruncate(fd, 8192));
    char data[32];
    CHECK(pread(fd, data, sizeof(data), 0) == sizeof(data));
    CHECK(!memcmp(data, "hel", 3));
    for (unsigned i = 3; i < sizeof(data); ++i)
        CHECK(!data[i]);
    CHECK(!link("/home/check/file", "/home/check/alias"));
    CHECK(!fstat(fd, &st) && st.st_nlink == 2);
    CHECK(!rename("/home/check/file", "/home/moved"));
    CHECK(!unlink("/home/check/alias"));
    CHECK(!unlink("/home/moved"));
    CHECK(!fstat(fd, &st) && st.st_nlink == 0);
    CHECK(pwrite(fd, "open", 4, 0) == 4);
    CHECK(!fchmod(fd, 0600));
    CHECK(!fstat(fd, &st) && (st.st_mode & 0777) == 0600);
    const struct timespec times[2] = {{123, 0}, {456, 0}};
    CHECK(!futimens(fd, times));
    CHECK(!fstat(fd, &st) && st.st_atime == 123 && st.st_mtime == 456);
    const struct timespec unchanged[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    CHECK(!futimens(fd, unchanged));
    CHECK(!fstat(fd, &st) && st.st_atime == 123 && st.st_mtime == 456);
    CHECK(!fsync(fd));
    CHECK(!close(fd));
    CHECK(!symlink("/home/check", "/home/link"));
    CHECK(readlink("/home/link", data, sizeof(data)) == 11);
    CHECK(!unlink("/home/link"));
    CHECK(!rmdir("/home/check"));
    fd = open("/home/persistent", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "kernel-persistent", 17) == 17);
    CHECK(!fsync(fd));
    CHECK(!close(fd));
    sync();
    done(1);
}
