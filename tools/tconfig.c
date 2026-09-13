#define _POSIX_C_SOURCE 200809L
#include "config_editor.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

/* Only VT100 CUP, ED and SGR sequences; no curses, terminfo or alternate screen. */
static struct termios original;
static bool terminal_active;
static volatile sig_atomic_t stopped, resized;
static int height = 24, width = 80;
enum { KEY_UP = 256, KEY_DOWN, KEY_REFRESH, KEY_END };

static void restore_terminal(void) {
    if (terminal_active) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
        fputs("\033[0m\033[H\033[2J", stdout);
        fflush(stdout);
        terminal_active = false;
    }
}

static void on_signal(int sig) {
    if (sig == SIGWINCH) resized = 1;
    else stopped = sig;
}

static int read_byte(int timeout) {
    struct pollfd fd = {.fd = STDIN_FILENO, .events = POLLIN};
    if (stopped) return KEY_END;
    if (resized) { resized = 0; return KEY_REFRESH; }
    int result = poll(&fd, 1, timeout);
    if (result < 0) return errno == EINTR ? KEY_REFRESH : KEY_END;
    if (!result) return -1;
    unsigned char c;
    return read(STDIN_FILENO, &c, 1) == 1 ? c : KEY_END;
}

static int read_key(void) {
    int c = read_byte(-1);
    if (c != 27) return c;
    c = read_byte(150);
    if (c == -1) return 27;
    if (c == KEY_END || c == KEY_REFRESH) return c;
    if (c != '[' && c != 'O') return KEY_REFRESH;
    /* Accept normal and application cursor keys, consume other CSI sequences. */
    for (int n = 0; n < 16; ++n) {
        c = read_byte(150);
        if (c < 0) return KEY_REFRESH;
        if (c >= 256) return c;
        if (c >= 0x40 && c <= 0x7e) {
            if (c == 'A') return KEY_UP;
            if (c == 'B') return KEY_DOWN;
            return KEY_REFRESH;
        }
    }
    return KEY_REFRESH;
}

static void screen_size(void) {
    struct winsize size;
    if (!ioctl(STDOUT_FILENO, TIOCGWINSZ, &size)) {
        height = size.ws_row ? size.ws_row : 24;
        width = size.ws_col ? size.ws_col : 80;
    }
}

static void line(int row, const char* text, bool selected) {
    if (row < 1 || row > height) return;
    printf("\033[%d;1H%s", row, selected ? "\033[7m" : "\033[0m");
    /* ASCII only, and leave the last column unused to avoid autowrap. */
    for (int i = 0; text[i] && i < width - 1; ++i) {
        unsigned char c = (unsigned char)text[i];
        putchar(c >= 32 && c < 127 ? c : '?');
    }
    fputs("\033[0m", stdout);
}

static void clear_screen(void) {
    screen_size();
    fputs("\033[0m\033[H\033[2J", stdout);
}

static bool edit_value(ConfigEditor* editor, size_t index) {
    char value[1024];
    if (strlen(editor->raw[index]) >= sizeof(value)) return false;
    strcpy(value, editor->raw[index]);
    size_t length = strlen(value);
    const Symbol* s = &editor->model.symbols[index];
    const char* error = "";
    for (;;) {
        clear_screen();
        line(1, s->prompt, true);
        line(2, "Enter accepts, Esc cancels, Backspace deletes, Ctrl-U clears", false);
        line(3, error, false);
        /* Show the tail while editing long values. */
        size_t shown = width > 2 ? (size_t)width - 2 : 1;
        line(4, value + (length > shown ? length - shown : 0), false);
        fflush(stdout);
        int key = read_key();
        if (key == KEY_END || key == 27) return false;
        if (key == '\r' || key == '\n') {
            long long number;
            if ((!strcmp(s->type, "int") || !strcmp(s->type, "hex")) &&
                !parse_number(value, &number)) {
                error = "Enter a valid signed 64-bit number.";
                continue;
            }
            editor_set(editor, index, value);
            return true;
        }
        if (key == 21) length = 0;
        else if ((key == 127 || key == 8) && length) --length;
        else if (key >= 32 && key < 127 && length + 1 < sizeof(value)) value[length++] = (char)key;
        value[length] = 0;
    }
}

static void help(const Symbol* symbol) {
    char* text = editor_help(symbol);
    clear_screen();
    line(1, symbol->prompt, true);
    int row = 3;
    char* state;
    for (char* part = strtok_r(text, "\n", &state); part; part = strtok_r(NULL, "\n", &state))
        line(row++, part, false);
    line(height, "Press any key to return", false);
    fflush(stdout);
    while (read_key() == KEY_REFRESH && !stopped) {}
    free(text);
}

static void run(ConfigEditor* editor) {
    size_t* rows = calloc(editor->model.count + 1, sizeof(*rows));
    if (!rows) { perror("calloc"); exit(1); }
    size_t count = 0, selected = 0, top = 0;
    for (size_t i = 0; i < editor->model.count; ++i)
        if (editor->model.symbols[i].prompt && *editor->model.symbols[i].prompt) rows[count++] = i;
    char message[512] = "";
    bool quitting = false;
    for (;;) {
        clear_screen();
        size_t visible = height > 7 ? (size_t)height - 7 : 1;
        if (selected < top) top = selected;
        if (selected >= top + visible) top = selected - visible + 1;
        char buffer[2048];
        snprintf(buffer, sizeof(buffer), "%s%s", editor->model.mainmenu,
                 editor_dirty(editor) ? " [modified]" : "");
        line(1, buffer, true);
        line(2, "Up/Down or j/k: move  Space/Enter: edit  y/n: set  ?: help", false);
        line(3, "s: save  q: quit   (- = unavailable)", false);
        if (height >= 8 && width >= 20) {
            for (size_t i = top; i < count && i < top + visible; ++i) {
                const Symbol* s = &editor->model.symbols[rows[i]];
                bool enabled = eval_depends(&editor->model, s->depends);
                const char* value = !strcmp(s->type, "bool") ?
                    (bool_value(s->value) ? "*" : " ") : s->value;
                snprintf(buffer, sizeof(buffer), "%c [%s] %s / %s", enabled ? ' ' : '-',
                         value, s->menu && *s->menu ? s->menu : "General", s->prompt);
                line(5 + (int)(i - top), buffer, i == selected);
            }
        } else line(4, "Terminal too small", false);
        if (!count) line(5, "No configurable options", false);
        snprintf(buffer, sizeof(buffer), "Option %zu/%zu", count ? selected + 1 : 0, count);
        line(height - 1, buffer, false);
        line(height, quitting ? "Save before exit? y: save  n: discard  Esc: cancel" : message, false);
        fflush(stdout);
        int key = read_key();
        if (key == KEY_END) break;
        if (key == KEY_REFRESH) continue;
        message[0] = 0;
        if (quitting) {
            if (key == 'n' || key == 'N') break;
            if (key == 'y' || key == 'Y') {
                if (editor_save(editor)) break;
                snprintf(message, sizeof(message), "%s", editor->error);
                quitting = false;
            } else if (key == 27) quitting = false;
            continue;
        }
        if (key == 'q' || key == 'Q' || key == 27) {
            if (!editor_dirty(editor)) break;
            quitting = true;
        } else if (key == 's' || key == 'S') {
            snprintf(message, sizeof(message), "%s", editor_save(editor) ? "Configuration saved." : editor->error);
        } else if (count) {
            size_t index = rows[selected];
            const Symbol* s = &editor->model.symbols[index];
            if (key == KEY_UP || key == 'k') selected = selected ? selected - 1 : count - 1;
            else if (key == KEY_DOWN || key == 'j') selected = (selected + 1) % count;
            else if (key == '?' || key == 'h') help(s);
            else if (key == ' ' || key == '\r' || key == '\n' || key == 'y' || key == 'n') {
                if (!eval_depends(&editor->model, s->depends)) {
                    snprintf(message, sizeof(message), "Unavailable: %s", s->depends);
                } else if (!strcmp(s->type, "bool")) {
                    editor_set(editor, index, key == 'y' ? "y" : key == 'n' ? "n" : bool_value(s->value) ? "n" : "y");
                } else if (key != 'y' && key != 'n') {
                    if (strlen(editor->raw[index]) >= 1024)
                        snprintf(message, sizeof(message), "Value too long to edit (maximum 1023 bytes).");
                    else edit_value(editor, index);
                }
            }
        }
    }
    free(rows);
}

int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor, argc, argv);
    if (result) return result < 0 ? 2 : 0;
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) || tcgetattr(STDIN_FILENO, &original)) {
        fprintf(stderr, "tconfig requires a VT100-compatible terminal on stdin and stdout.\n");
        editor_free(&editor);
        return 1;
    }
    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGWINCH, &action, NULL);
    struct termios raw = original;
    raw.c_lflag &= ~(ICANON | ECHO | ECHONL | IEXTEN);
    raw.c_iflag &= ~(IXON | ICRNL | INLCR | IGNCR);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    atexit(restore_terminal);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw)) {
        perror("tcsetattr");
        editor_free(&editor);
        return 1;
    }
    terminal_active = true;
    run(&editor);
    restore_terminal();
    editor_free(&editor);
    return stopped ? 128 + stopped : 0;
}
