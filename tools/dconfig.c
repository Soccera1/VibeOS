#define _GNU_SOURCE
#include "config_editor.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 12

/* Never interpret terminal capabilities or emit control bytes from values. */
static void plain(const char* text) {
    for (; text && *text; ++text) {
        unsigned char c = (unsigned char)*text;
        putchar(c >= 32 && c < 127 ? c : '?');
    }
}

static char* read_line(const char* prompt) {
    char* line = NULL;
    size_t capacity = 0;
    fputs(prompt, stdout);
    fflush(stdout);
    ssize_t length = getline(&line, &capacity, stdin);
    if (length < 0) { free(line); return NULL; }
    if (length && line[length - 1] == '\n') line[--length] = 0;
    if (length && line[length - 1] == '\r') line[--length] = 0;
    return line;
}

static void show(ConfigEditor* e, const size_t* rows, size_t count, size_t page) {
    putchar('\n');
    plain(e->model.mainmenu);
    printf("%s - page %zu/%zu\n", editor_dirty(e) ? " [modified]" : "",
           page + 1, count ? (count + PAGE_SIZE - 1) / PAGE_SIZE : 1);
    for (size_t n = page * PAGE_SIZE; n < count && n < (page + 1) * PAGE_SIZE; ++n) {
        const Symbol* s = &e->model.symbols[rows[n]];
        printf("%zu. [%s", n + 1, eval_depends(&e->model, s->depends) ? "" : "unavailable: ");
        plain(s->value);
        fputs("] ", stdout);
        if (s->menu && *s->menu) { plain(s->menu); fputs(" / ", stdout); }
        plain(s->prompt);
        putchar('\n');
    }
    puts("Number: edit; h NUMBER: help; n/p: page; l: list; s: save; q: quit");
}

static void edit(ConfigEditor* e, size_t index) {
    const Symbol* s = &e->model.symbols[index];
    if (!eval_depends(&e->model, s->depends)) {
        fputs("Unavailable: ", stdout); plain(s->depends); putchar('\n');
        return;
    }
    plain(s->prompt); fputs(" (", stdout); plain(s->type); puts(")");
    puts("Enter a value; blank keeps the current value; \"\" sets an empty string.");
    char* line = read_line("Value> ");
    if (!line) return;
    bool string = !strcmp(s->type, "string");
    char* value = string ? line : trim(line);
    long long number;
    if (!*value) { free(line); return; }
    if (!strcmp(s->type, "bool") && strcmp(value, "y") && strcmp(value, "n")) {
        puts("Enter y or n.");
    } else if ((!strcmp(s->type, "int") || !strcmp(s->type, "hex")) && !parse_number(value, &number)) {
        puts("Enter a valid signed 64-bit number.");
    } else {
        editor_set(e, index, string && !strcmp(value, "\"\"") ? "" : value);
    }
    free(line);
}

static bool save(ConfigEditor* e) {
    if (editor_save(e)) { puts("Configuration saved."); return true; }
    plain(e->error); putchar('\n');
    return false;
}

int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor, argc, argv);
    if (result) return result < 0 ? 1 : 0;
    size_t* rows = calloc(editor.model.count + 1, sizeof(*rows));
    if (!rows) { perror("calloc"); editor_free(&editor); return 1; }
    size_t count = 0, page = 0;
    for (size_t i = 0; i < editor.model.count; ++i)
        if (editor.model.symbols[i].prompt) rows[count++] = i;
    puts("dconfig - line-oriented configuration (commands require Enter)");
    for (;;) {
        show(&editor, rows, count, page);
        char* line = read_line("Command> ");
        if (!line) break;
        char* command = trim(line);
        bool quit = false;
        if (!strcmp(command, "q")) {
            if (!editor_dirty(&editor)) quit = true;
            else {
                char* answer = read_line("Save before exit? [y: save, n: discard, Enter: cancel]> ");
                if (answer) {
                    char* choice = trim(answer);
                    if (!strcmp(choice, "n")) quit = true;
                    else if (!strcmp(choice, "y")) quit = save(&editor);
                    free(answer);
                }
            }
        } else if (!strcmp(command, "s")) save(&editor);
        else if (!strcmp(command, "n")) { if ((page + 1) * PAGE_SIZE < count) ++page; }
        else if (!strcmp(command, "p")) { if (page) --page; }
        else if (*command && strcmp(command, "l")) {
            bool help = command[0] == 'h' && isspace((unsigned char)command[1]);
            char* number = help ? trim(command + 1) : command;
            char* end;
            errno = 0;
            unsigned long long row = strtoull(number, &end, 10);
            if (!isdigit((unsigned char)*number) || *end || errno || row < 1 || row > count) {
                puts("Enter an option number or one of the listed commands.");
            } else {
                size_t index = rows[row - 1];
                page = ((size_t)row - 1) / PAGE_SIZE;
                if (help) {
                    char* info = editor_help(&editor.model.symbols[index]);
                    for (char* part = strtok(info, "\n"); part; part = strtok(NULL, "\n")) {
                        plain(part); putchar('\n');
                    }
                    free(info);
                } else edit(&editor, index);
            }
        }
        free(line);
        if (quit) break;
    }
    if (editor_dirty(&editor)) puts("Unsaved changes discarded.");
    result = ferror(stdin) ? 1 : 0;
    free(rows);
    editor_free(&editor);
    return result;
}
