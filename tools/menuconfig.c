#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <ncurses.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* name;
    char* type;
    char* prompt;
    char* defval;
    char* depends;
    char* menu;
    char* value;
} Symbol;

typedef struct {
    char* mainmenu;
    Symbol* symbols;
    size_t count;
    size_t capacity;
} Model;

typedef struct {
    bool is_menu;
    int symbol_index;
    const char* menu;
} Row;

static char* xstrdup(const char* s) {
    char* copy = strdup(s ? s : "");
    if (!copy) {
        perror("strdup");
        exit(1);
    }
    return copy;
}

static char* trim(char* s) {
    while (isspace((unsigned char)*s)) {
        ++s;
    }
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static bool starts_with(const char* s, const char* prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static char* unquote(const char* s) {
    char* tmp = xstrdup(s);
    char* value = trim(tmp);
    size_t len = strlen(value);
    if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
        value[len - 1] = '\0';
        char* out = xstrdup(value + 1);
        free(tmp);
        return out;
    }
    char* out = xstrdup(value);
    free(tmp);
    return out;
}

static void set_string(char** dst, const char* value) {
    free(*dst);
    *dst = xstrdup(value);
}

static void model_add_symbol(Model* model, const char* name, const char* menu) {
    if (model->count == model->capacity) {
        size_t next = model->capacity ? model->capacity * 2 : 16;
        Symbol* symbols = realloc(model->symbols, next * sizeof(*symbols));
        if (!symbols) {
            perror("realloc");
            exit(1);
        }
        model->symbols = symbols;
        model->capacity = next;
    }
    Symbol* sym = &model->symbols[model->count++];
    memset(sym, 0, sizeof(*sym));
    sym->name = xstrdup(name);
    sym->type = xstrdup("bool");
    sym->menu = xstrdup(menu);
}

static char* join_menu(char** stack, size_t depth) {
    if (depth == 0) {
        return xstrdup("");
    }
    size_t len = 1;
    for (size_t i = 0; i < depth; ++i) {
        len += strlen(stack[i]) + 3;
    }
    char* out = calloc(len, 1);
    if (!out) {
        perror("calloc");
        exit(1);
    }
    for (size_t i = 0; i < depth; ++i) {
        if (i != 0) {
            strcat(out, " / ");
        }
        strcat(out, stack[i]);
    }
    return out;
}

static Model parse_kconfig(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
        exit(1);
    }

    Model model = {0};
    model.mainmenu = xstrdup("Configuration");
    char* menu_stack[64] = {0};
    size_t menu_depth = 0;
    Symbol* current = NULL;
    char* line = NULL;
    size_t cap = 0;

    while (getline(&line, &cap, f) >= 0) {
        char* s = trim(line);
        if (*s == '\0' || *s == '#') {
            continue;
        }
        if (starts_with(s, "mainmenu ")) {
            set_string(&model.mainmenu, unquote(s + 9));
            continue;
        }
        if (starts_with(s, "menu ")) {
            if (menu_depth >= 64) {
                fprintf(stderr, "%s: menu nesting too deep\n", path);
                exit(1);
            }
            menu_stack[menu_depth++] = unquote(s + 5);
            continue;
        }
        if (strcmp(s, "endmenu") == 0) {
            if (menu_depth == 0) {
                fprintf(stderr, "%s: endmenu without menu\n", path);
                exit(1);
            }
            free(menu_stack[--menu_depth]);
            menu_stack[menu_depth] = NULL;
            continue;
        }
        if (starts_with(s, "config ")) {
            char* menu = join_menu(menu_stack, menu_depth);
            model_add_symbol(&model, trim(s + 7), menu);
            free(menu);
            current = &model.symbols[model.count - 1];
            continue;
        }
        if (!current) {
            continue;
        }
        if (starts_with(s, "bool")) {
            set_string(&current->type, "bool");
            char* rest = trim(s + 4);
            if (*rest) {
                set_string(&current->prompt, unquote(rest));
            }
        } else if (starts_with(s, "string")) {
            set_string(&current->type, "string");
            char* rest = trim(s + 6);
            if (*rest) {
                set_string(&current->prompt, unquote(rest));
            }
        } else if (starts_with(s, "int")) {
            set_string(&current->type, "int");
            char* rest = trim(s + 3);
            if (*rest) {
                set_string(&current->prompt, unquote(rest));
            }
        } else if (starts_with(s, "hex")) {
            set_string(&current->type, "hex");
            char* rest = trim(s + 3);
            if (*rest) {
                set_string(&current->prompt, unquote(rest));
            }
        } else if (starts_with(s, "prompt ")) {
            set_string(&current->prompt, unquote(s + 7));
        } else if (starts_with(s, "default ")) {
            set_string(&current->defval, unquote(s + 8));
        } else if (starts_with(s, "depends on ")) {
            set_string(&current->depends, trim(s + 11));
        }
    }

    free(line);
    for (size_t i = 0; i < menu_depth; ++i) {
        free(menu_stack[i]);
    }
    fclose(f);
    return model;
}

static int find_symbol(const Model* model, const char* name) {
    for (size_t i = 0; i < model->count; ++i) {
        if (strcmp(model->symbols[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static char* config_string_value(const char* raw) {
    char* value = xstrdup(raw);
    char* s = trim(value);
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        char* out = xstrdup(s + 1);
        free(value);
        return out;
    }
    char* out = xstrdup(s);
    free(value);
    return out;
}

static void parse_config(Model* model, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        return;
    }
    char* line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) >= 0) {
        char* s = trim(line);
        if (starts_with(s, "CONFIG_")) {
            char* eq = strchr(s, '=');
            if (!eq) {
                continue;
            }
            *eq = '\0';
            int idx = find_symbol(model, s + 7);
            if (idx >= 0) {
                char* value = config_string_value(eq + 1);
                set_string(&model->symbols[idx].value, value);
                free(value);
            }
        } else if (starts_with(s, "# CONFIG_")) {
            char* end = strstr(s, " is not set");
            if (!end) {
                continue;
            }
            *end = '\0';
            int idx = find_symbol(model, s + 9);
            if (idx >= 0) {
                set_string(&model->symbols[idx].value, "n");
            }
        }
    }
    free(line);
    fclose(f);
}

static bool bool_value(const char* value) {
    return value && strcmp(value, "y") == 0;
}

static bool eval_depends(const Model* model, const char* expr) {
    if (!expr || !*expr) {
        return true;
    }
    char* copy = xstrdup(expr);
    char* saveptr = NULL;
    bool result = true;
    bool pending_or = false;
    for (char* tok = strtok_r(copy, " \t()", &saveptr); tok; tok = strtok_r(NULL, " \t()", &saveptr)) {
        if (strcmp(tok, "&&") == 0) {
            continue;
        }
        if (strcmp(tok, "||") == 0) {
            pending_or = true;
            continue;
        }
        bool neg = false;
        if (tok[0] == '!') {
            neg = true;
            ++tok;
        }
        bool value = false;
        if (strcmp(tok, "y") == 0) {
            value = true;
        } else if (strcmp(tok, "n") == 0) {
            value = false;
        } else {
            int idx = find_symbol(model, tok);
            value = idx >= 0 && bool_value(model->symbols[idx].value);
        }
        if (neg) {
            value = !value;
        }
        if (pending_or) {
            result = result || value;
            pending_or = false;
        } else {
            result = result && value;
        }
    }
    free(copy);
    return result;
}

static void resolve(Model* model) {
    for (size_t i = 0; i < model->count; ++i) {
        Symbol* sym = &model->symbols[i];
        if (!eval_depends(model, sym->depends)) {
            set_string(&sym->value, strcmp(sym->type, "bool") == 0 ? "n" : "");
            continue;
        }
        if (!sym->value || !*sym->value) {
            if (sym->defval) {
                set_string(&sym->value, sym->defval);
            } else {
                set_string(&sym->value, strcmp(sym->type, "bool") == 0 ? "n" : "");
            }
        }
        if (strcmp(sym->type, "bool") == 0 && strcmp(sym->value, "y") != 0) {
            set_string(&sym->value, "n");
        }
    }
}

static void fprint_quoted(FILE* f, const char* value) {
    fputc('"', f);
    for (const char* p = value; p && *p; ++p) {
        if (*p == '\\' || *p == '"') {
            fputc('\\', f);
        }
        fputc(*p, f);
    }
    fputc('"', f);
}

static void write_config(const Model* model, const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) {
        endwin();
        fprintf(stderr, "failed to write %s: %s\n", path, strerror(errno));
        exit(1);
    }
    fprintf(f, "# %s\n# Generated by tools/menuconfig.c\n\n", model->mainmenu);
    const char* current_menu = NULL;
    for (size_t i = 0; i < model->count; ++i) {
        const Symbol* sym = &model->symbols[i];
        if (!current_menu || strcmp(current_menu, sym->menu) != 0) {
            current_menu = sym->menu;
            if (*current_menu) {
                fprintf(f, "#\n# %s\n#\n", current_menu);
            }
        }
        if (strcmp(sym->type, "bool") == 0) {
            if (bool_value(sym->value)) {
                fprintf(f, "CONFIG_%s=y\n", sym->name);
            } else {
                fprintf(f, "# CONFIG_%s is not set\n", sym->name);
            }
        } else if (strcmp(sym->type, "string") == 0) {
            fprintf(f, "CONFIG_%s=", sym->name);
            fprint_quoted(f, sym->value);
            fputc('\n', f);
        } else {
            fprintf(f, "CONFIG_%s=%s\n", sym->name, sym->value ? sym->value : "");
        }
    }
    fclose(f);
}

static Row* build_rows(Model* model, size_t* out_count) {
    Row* rows = calloc(model->count * 2 + 1, sizeof(*rows));
    if (!rows) {
        perror("calloc");
        exit(1);
    }
    size_t count = 0;
    const char* current_menu = NULL;
    for (size_t i = 0; i < model->count; ++i) {
        Symbol* sym = &model->symbols[i];
        if (!eval_depends(model, sym->depends)) {
            continue;
        }
        if (!current_menu || strcmp(current_menu, sym->menu) != 0) {
            current_menu = sym->menu;
            rows[count++] = (Row){.is_menu = true, .symbol_index = -1, .menu = *current_menu ? current_menu : "General"};
        }
        rows[count++] = (Row){.is_menu = false, .symbol_index = (int)i, .menu = NULL};
    }
    *out_count = count;
    return rows;
}

static int clamp_selection(const Row* rows, size_t count, int selected) {
    int first = -1;
    int nearest = -1;
    int nearest_distance = 1000000;
    for (size_t i = 0; i < count; ++i) {
        if (rows[i].is_menu) {
            continue;
        }
        if (first < 0) {
            first = (int)i;
        }
        int distance = abs((int)i - selected);
        if (distance < nearest_distance) {
            nearest = (int)i;
            nearest_distance = distance;
        }
        if ((int)i == selected) {
            return selected;
        }
    }
    return nearest >= 0 ? nearest : first >= 0 ? first : 0;
}

static void centered(WINDOW* win, int y, const char* text, int attr) {
    int height, width;
    getmaxyx(win, height, width);
    (void)height;
    int x = (width - (int)strlen(text)) / 2;
    if (x < 1) {
        x = 1;
    }
    wattron(win, attr);
    mvwaddnstr(win, y, x, text, width - x - 1);
    wattroff(win, attr);
}

static bool confirm_dialog(const char* question) {
    int height, width;
    getmaxyx(stdscr, height, width);
    int w = (int)strlen(question) + 10;
    if (w < 48) {
        w = 48;
    }
    if (w > width - 4) {
        w = width - 4;
    }
    int h = 7;
    WINDOW* win = newwin(h, w, (height - h) / 2, (width - w) / 2);
    keypad(win, true);
    for (;;) {
        werase(win);
        box(win, 0, 0);
        centered(win, 1, "Confirm", A_BOLD);
        centered(win, 3, question, A_NORMAL);
        centered(win, 5, "<Y> Yes    <N> No", A_REVERSE);
        wrefresh(win);
        int key = wgetch(win);
        if (key == 'y' || key == 'Y') {
            delwin(win);
            return true;
        }
        if (key == 'n' || key == 'N' || key == 27) {
            delwin(win);
            return false;
        }
    }
}

static void help_dialog(const Symbol* sym) {
    int height, width;
    getmaxyx(stdscr, height, width);
    int w = width > 76 ? 76 : width - 4;
    int h = 12;
    WINDOW* win = newwin(h, w, (height - h) / 2, (width - w) / 2);
    keypad(win, true);
    werase(win);
    box(win, 0, 0);
    centered(win, 0, " Help ", A_BOLD);
    mvwprintw(win, 2, 2, "Symbol: CONFIG_%s", sym->name);
    mvwprintw(win, 3, 2, "Type: %s", sym->type);
    mvwprintw(win, 4, 2, "Prompt: %s", sym->prompt ? sym->prompt : sym->name);
    if (sym->defval) {
        mvwprintw(win, 5, 2, "Default: %s", sym->defval);
    }
    if (sym->menu && *sym->menu) {
        mvwprintw(win, 6, 2, "Location: %s", sym->menu);
    }
    if (sym->depends) {
        mvwprintw(win, 7, 2, "Depends on: %s", sym->depends);
    }
    centered(win, h - 2, "< Press any key >", A_REVERSE);
    wrefresh(win);
    wgetch(win);
    delwin(win);
}

static void edit_value_dialog(Symbol* sym) {
    int height, width;
    getmaxyx(stdscr, height, width);
    int w = width > 70 ? 70 : width - 4;
    int h = 8;
    WINDOW* win = newwin(h, w, (height - h) / 2, (width - w) / 2);
    keypad(win, true);
    echo();
    curs_set(1);
    werase(win);
    box(win, 0, 0);
    centered(win, 1, sym->prompt ? sym->prompt : sym->name, A_BOLD);
    mvwprintw(win, 3, 2, "CONFIG_%s", sym->name);
    mvwaddstr(win, 5, 2, "> ");
    if (sym->value) {
        waddnstr(win, sym->value, w - 6);
    }
    wmove(win, 5, 4 + (sym->value ? (int)strlen(sym->value) : 0));
    wrefresh(win);
    char buf[512] = {0};
    wgetnstr(win, buf, (int)sizeof(buf) - 1);
    noecho();
    curs_set(0);
    if (buf[0]) {
        set_string(&sym->value, buf);
    }
    delwin(win);
}

static char* row_label(const Symbol* sym) {
    char buf[1024];
    if (strcmp(sym->type, "bool") == 0) {
        snprintf(buf, sizeof(buf), "%s %s", bool_value(sym->value) ? "[*]" : "[ ]", sym->prompt ? sym->prompt : sym->name);
    } else {
        snprintf(buf, sizeof(buf), "(%s) %s", sym->value ? sym->value : "", sym->prompt ? sym->prompt : sym->name);
    }
    return xstrdup(buf);
}

static void run_menu(Model* model, const char* config_path) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, true);
    curs_set(0);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_BLACK, COLOR_WHITE);
        init_pair(2, COLOR_CYAN, -1);
    }

    int selected = 0;
    int top = 0;
    bool dirty = false;
    char message[256] = {0};

    for (;;) {
        size_t row_count = 0;
        Row* rows = build_rows(model, &row_count);
        selected = clamp_selection(rows, row_count, selected);

        int height, width;
        getmaxyx(stdscr, height, width);
        int visible = height - 8;
        if (visible < 1 || width < 54) {
            erase();
            mvaddstr(0, 0, "Terminal too small for menuconfig");
            refresh();
            int key = getch();
            free(rows);
            if (key == 'q' || key == 'Q' || key == 27) {
                break;
            }
            continue;
        }
        if (selected < top) {
            top = selected;
        }
        if (selected >= top + visible) {
            top = selected - visible + 1;
        }
        if (top < 0) {
            top = 0;
        }

        erase();
        box(stdscr, 0, 0);
        char title[512];
        snprintf(title, sizeof(title), " %s ", model->mainmenu);
        centered(stdscr, 0, title, A_BOLD);
        centered(stdscr, 2, "Arrow keys navigate, Space selects, Enter edits, S saves, Q exits", A_NORMAL);

        int menu_attr = has_colors() ? COLOR_PAIR(2) | A_BOLD : A_BOLD;
        int selected_attr = has_colors() ? COLOR_PAIR(1) : A_REVERSE;
        for (int i = top, screen_row = 4; i < (int)row_count && screen_row < 4 + visible; ++i, ++screen_row) {
            if (rows[i].is_menu) {
                attron(menu_attr);
                mvprintw(screen_row, 4, "--- %s ---", rows[i].menu);
                attroff(menu_attr);
            } else {
                Symbol* sym = &model->symbols[rows[i].symbol_index];
                char* label = row_label(sym);
                if (i == selected) {
                    attron(selected_attr);
                }
                mvaddnstr(screen_row, 4, label, width - 8);
                if (i == selected) {
                    attroff(selected_attr);
                }
                free(label);
            }
        }
        if (top > 0) {
            centered(stdscr, 3, "(-)", A_NORMAL);
        }
        if (top + visible < (int)row_count) {
            centered(stdscr, height - 4, "(+)", A_NORMAL);
        }
        if (dirty) {
            mvaddnstr(height - 3, 2, "Modified", width - 4);
        }
        if (message[0]) {
            mvaddnstr(height - 2, 2, message, width - 4);
        }
        centered(stdscr, height - 1, "<Select> <Exit> <Help> <Save>", A_REVERSE);
        refresh();

        int key = getch();
        message[0] = '\0';

        if (key == KEY_UP || key == 'k' || key == 'K') {
            int next = selected;
            do {
                next = next <= 0 ? (int)row_count - 1 : next - 1;
            } while (row_count > 0 && rows[next].is_menu);
            selected = next;
        } else if (key == KEY_DOWN || key == 'j' || key == 'J') {
            int next = selected;
            do {
                next = next + 1 >= (int)row_count ? 0 : next + 1;
            } while (row_count > 0 && rows[next].is_menu);
            selected = next;
        } else if ((key == ' ' || key == '\n' || key == KEY_ENTER) && row_count > 0 && !rows[selected].is_menu) {
            Symbol* sym = &model->symbols[rows[selected].symbol_index];
            if (strcmp(sym->type, "bool") == 0) {
                set_string(&sym->value, bool_value(sym->value) ? "n" : "y");
            } else {
                edit_value_dialog(sym);
            }
            resolve(model);
            dirty = true;
        } else if ((key == 'h' || key == 'H' || key == '?') && row_count > 0 && !rows[selected].is_menu) {
            help_dialog(&model->symbols[rows[selected].symbol_index]);
        } else if (key == 's' || key == 'S') {
            write_config(model, config_path);
            dirty = false;
            snprintf(message, sizeof(message), "Wrote %s", config_path);
        } else if (key == 'q' || key == 'Q' || key == 27) {
            if (!dirty) {
                free(rows);
                break;
            }
            if (confirm_dialog("Save configuration before exit?")) {
                write_config(model, config_path);
                free(rows);
                break;
            }
            if (confirm_dialog("Exit without saving changes?")) {
                free(rows);
                break;
            }
        }
        free(rows);
    }
    endwin();
}

static void usage(const char* argv0) {
    fprintf(stderr, "usage: %s [--kconfig Kconfig] [--config .config]\n", argv0);
}

int main(int argc, char** argv) {
    const char* kconfig_path = "Kconfig";
    const char* config_path = ".config";
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--kconfig") == 0 && i + 1 < argc) {
            kconfig_path = argv[++i];
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    Model model = parse_kconfig(kconfig_path);
    parse_config(&model, config_path);
    resolve(&model);
    run_menu(&model, config_path);
    return 0;
}
