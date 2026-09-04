#include <stdio.h>

#include "../kernel/src/fs.c"

int main(void) {
    int result = ramdisk_mount_tmp();
#ifdef CONFIG_KERNEL_TMP_RAMDISK
    if (result != 0 || !path_in_ramdisk("/tmp/test")) return 1;
    if ((ramdisk_find_path("/tmp")->mode & 07777u) != 01777u) return 1;
#else
    if (result != -EROFS || path_in_ramdisk("/tmp/test")) return 1;
#endif
    result = ramdisk_mount_home();
#ifdef CONFIG_KERNEL_HOME_RAMDISK
    if (result != 0 || !fs_home_ramdisk_ready() || !path_in_ramdisk("/home/user")) return 1;
#else
    if (result != -EROFS || fs_home_ramdisk_ready() || path_in_ramdisk("/home/user")) return 1;
#endif
    puts("kernel filesystem config checks passed");
    return 0;
}
