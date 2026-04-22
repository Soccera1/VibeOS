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
        "  ls /bin              see the essential GNU and BusyBox commands\n"
        "  ls /usr/bin          see the rest of the GNU and standalone tools\n"
        "  busybox --list       list BusyBox applets\n"
        "  busybox --list-full  show the remaining BusyBox applet paths\n"
        "  file /usr/bin/bash   identify a file with libmagic\n"
        "  ls /usr/share/man    browse the staged manual page tree\n"
        "  man intro            read the manual with man and groff\n"
        "\n"
        "Notes:\n"
        "  This help is curated on purpose; it is not a full command dump.\n"
        "  In Bash, use: builtin help <name> for builtin docs.\n");
    return 0;
}
