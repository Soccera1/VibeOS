#include "libc.h"

#define MAX_ARGS 16
#define MAX_CMD_LEN 128

static char* argv[MAX_ARGS];
static int argc;

static void parse_command(char* line) {
    argc = 0;
    char* ptr = line;
    while (*ptr && argc < MAX_ARGS) {
        while (*ptr == ' ') ptr++;
        if (*ptr == '\0') break;

        if (*ptr == '"' || *ptr == '\'') {
            char quote = *ptr++;
            argv[argc++] = ptr;
            while (*ptr && *ptr != quote) ptr++;
            if (*ptr) *ptr++ = '\0';
        } else {
            argv[argc++] = ptr;
            while (*ptr && *ptr != ' ') ptr++;
            if (*ptr) *ptr++ = '\0';
        }
    }
}

int main() {
    char line[MAX_CMD_LEN];
    int line_idx = 0;

    puts("\nVibeOS User-Mode Shell v0.7\n");
    puts("Ready.\n\n");

    while (1) {
        puts("vibe$ ");
        line_idx = 0;
        
        while (1) {
            char c;
            int n = read(0, &c, 1);
            if (n <= 0) continue;
            
            if (c == '\n' || c == '\r') {
                putchar('\n');
                line[line_idx] = '\0';
                break;
            } else if (c == '\b' || c == 127) {
                if (line_idx > 0) {
                    line_idx--;
                    putchar('\b');
                }
            } else if ((unsigned char)c >= 32 && (unsigned char)c <= 126) {
                if (line_idx < MAX_CMD_LEN - 1) {
                    line[line_idx++] = c;
                    putchar(c);
                }
            }
        }

        if (line_idx == 0) continue;

        parse_command(line);
        if (argc == 0) continue;

        char* cmd = argv[0];

        if (strcmp(cmd, "ls") == 0) {
            ls();
        } else if (strcmp(cmd, "help") == 0) {
            puts("Built-ins: ls, help, exit, exec <file>\n");
        } else if (strcmp(cmd, "exit") == 0) {
            exit(0);
        } else if (strcmp(cmd, "exec") == 0) {
            if (argc < 2) {
                puts("Usage: exec <filename>\n");
            } else {
                exec(argv[1]);
                puts("exec: command not found\n");
            }
        } else {
            puts("sh: unknown command: ");
            puts(cmd);
            puts("\n");
        }
    }
    return 0;
}