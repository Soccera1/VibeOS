#include <unistd.h>

static void write_all(const char* s) {
    const char* p = s;
    while (*p != '\0') {
        ++p;
    }
    (void)write(STDOUT_FILENO, s, (size_t)(p - s));
}

int main(void) {
    write_all(
        "VibeOS userspace quick start\n"
        "\n"
        "Start here:\n"
        "  uname -a        show kernel and machine info\n"
        "  pwd             print the current directory\n"
        "  ls /            inspect the root filesystem\n"
        "  ls /bin         see the essential command set\n"
        "  ls /usr/bin     see optional programs shipped under /usr\n"
        "  cat /etc/motd   reread the welcome message\n"
        "\n"
        "Shells:\n"
        "  bash            preferred interactive shell when available in /usr\n"
        "  sh              BusyBox shell\n"
        "  busybox         run BusyBox directly\n"
        "\n"
        "Finding commands:\n"
        "  busybox --list       list BusyBox applets\n"
        "  busybox --list-full  show their installed paths\n"
        "  file /usr/bin/bash   identify a file with libmagic\n"
        "\n"
        "Notes:\n"
        "  This help is curated on purpose; it is not a full command dump.\n"
        "  In Bash, use: builtin help <name> for builtin docs.\n");
    return 0;
}
