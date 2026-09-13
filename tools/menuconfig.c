#define _GNU_SOURCE
#include "kconfig.h"
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool is_menu;
    int symbol_index;
    const char* menu;
} Row;

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
        if (!sym->prompt || !*sym->prompt || !eval_depends(model, sym->depends)) {
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
            if (write_config(model, config_path) == 0) {
                dirty = false;
                snprintf(message, sizeof(message), "Wrote %s", config_path);
            } else snprintf(message, sizeof(message), "Cannot save %s", config_path);
        } else if (key == 'q' || key == 'Q' || key == 27) {
            if (!dirty) {
                free(rows);
                break;
            }
            if (confirm_dialog("Save configuration before exit?")) {
                if (write_config(model, config_path) == 0) {
                    free(rows);
                    break;
                }
                snprintf(message, sizeof(message), "Cannot save %s", config_path);
                free(rows);
                continue;
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
    free_model(&model);
    return 0;
}
