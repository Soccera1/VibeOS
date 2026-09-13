#define _GNU_SOURCE
#include "kconfig.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

char* xstrdup(const char* s) {
    char* copy = strdup(s ? s : "");
    if (!copy) {
        perror("strdup");
        exit(1);
    }
    return copy;
}

char* trim(char* s) {
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
        char *read = out, *write = out;
        while (*read) {
            if (*read == '\\' && (read[1] == '\\' || read[1] == '"')) ++read;
            *write++ = *read++;
        }
        *write = 0;
        free(tmp);
        return out;
    }
    char* out = xstrdup(value);
    free(tmp);
    return out;
}

void set_string(char** dst, const char* value) {
    char* copy = xstrdup(value);
    free(*dst);
    *dst = copy;
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

Model parse_kconfig(const char* path) {
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
            free(model.mainmenu);
            model.mainmenu = unquote(s + 9);
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
            const char* name = trim(s + 7);
            if (!*name || strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != strlen(name)) {
                fprintf(stderr, "%s: invalid symbol name: %s\n", path, name);
                exit(1);
            }
            char* menu = join_menu(menu_stack, menu_depth);
            model_add_symbol(&model, trim(s + 7), menu);
            free(menu);
            current = &model.symbols[model.count - 1];
            continue;
        }
        if (!current) {
            fprintf(stderr, "%s: property outside config: %s\n", path, s);
            exit(1);
        }
        if (starts_with(s, "bool") && (!s[4] || isspace((unsigned char)s[4]))) {
            set_string(&current->type, "bool");
            char* rest = trim(s + 4);
            if (*rest) {
                free(current->prompt); current->prompt = unquote(rest);
            }
        } else if (starts_with(s, "string") && (!s[6] || isspace((unsigned char)s[6]))) {
            set_string(&current->type, "string");
            char* rest = trim(s + 6);
            if (*rest) {
                free(current->prompt); current->prompt = unquote(rest);
            }
        } else if (starts_with(s, "int") && (!s[3] || isspace((unsigned char)s[3]))) {
            set_string(&current->type, "int");
            char* rest = trim(s + 3);
            if (*rest) {
                free(current->prompt); current->prompt = unquote(rest);
            }
        } else if (starts_with(s, "hex") && (!s[3] || isspace((unsigned char)s[3]))) {
            set_string(&current->type, "hex");
            char* rest = trim(s + 3);
            if (*rest) {
                free(current->prompt); current->prompt = unquote(rest);
            }
        } else if (starts_with(s, "prompt ")) {
            free(current->prompt); current->prompt = unquote(s + 7);
        } else if (starts_with(s, "default ")) {
            free(current->defval); current->defval = unquote(s + 8);
        } else if (starts_with(s, "depends on ")) {
            set_string(&current->depends, trim(s + 11));
        } else {
            fprintf(stderr, "%s: unsupported Kconfig line: %s\n", path, s);
            exit(1);
        }
    }

    if (ferror(f)) { fprintf(stderr, "%s: read failed\n", path); exit(1); }
    free(line);
    for (size_t i = 0; i < menu_depth; ++i) {
        free(menu_stack[i]);
    }
    fclose(f);
    return model;
}

int find_symbol(const Model* model, const char* name) {
    for (size_t i = 0; i < model->count; ++i) {
        if (strcmp(model->symbols[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

void parse_config(Model* model, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        if (errno != ENOENT) { fprintf(stderr, "%s: %s\n", path, strerror(errno)); exit(1); }
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
                char* value = unquote(eq + 1);
                set_string(&model->symbols[idx].value, value);
                free(value);
            }
        } else if (starts_with(s, "# CONFIG_")) {
            char* end = strstr(s, " is not set");
            if (!end || end[strlen(" is not set")]) {
                continue;
            }
            *end = '\0';
            int idx = find_symbol(model, s + 9);
            if (idx >= 0) {
                set_string(&model->symbols[idx].value, "n");
            }
        }
    }
    if (ferror(f)) { fprintf(stderr, "%s: read failed\n", path); exit(1); }
    free(line);
    fclose(f);
}

bool bool_value(const char* value) {
    return value && strcmp(value, "y") == 0;
}

typedef struct { const Model* model; const char* p; size_t limit; } Expr;
static void spaces(Expr* e) { while (isspace((unsigned char)*e->p)) ++e->p; }
static bool expr_or(Expr* e);
static bool primary(Expr* e) {
    spaces(e);
    if (*e->p == '!') { ++e->p; return !primary(e); }
    if (*e->p == '(') {
        ++e->p;
        bool value = expr_or(e);
        spaces(e);
        if (*e->p == ')') ++e->p;
        return value;
    }
    const char* start = e->p;
    while (isalnum((unsigned char)*e->p) || *e->p == '_') ++e->p;
    size_t len = (size_t)(e->p - start);
    if (len == 1 && *start == 'y') return true;
    for (size_t i = 0; i < e->limit; ++i)
        if (strlen(e->model->symbols[i].name) == len &&
            strncmp(start, e->model->symbols[i].name, len) == 0)
            return bool_value(e->model->symbols[i].value);
    return false;
}
static bool expr_and(Expr* e) {
    bool result = primary(e);
    spaces(e);
    while (strncmp(e->p, "&&", 2) == 0) {
        e->p += 2;
        bool right = primary(e);
        result = result && right;
        spaces(e);
    }
    return result;
}
static bool expr_or(Expr* e) {
    bool result = expr_and(e);
    spaces(e);
    while (strncmp(e->p, "||", 2) == 0) {
        e->p += 2;
        bool right = expr_and(e);
        result = result || right;
        spaces(e);
    }
    return result;
}
static bool depends_until(const Model* model, const char* expr, size_t limit) {
    if (!expr || !*expr) return true;
    Expr e = {model, expr, limit};
    return expr_or(&e);
}
bool eval_depends(const Model* model, const char* expr) {
    return depends_until(model, expr, model->count);
}
bool parse_number(const char* value, long long* number) {
    if (!value) return false;
    while (isspace((unsigned char)*value)) ++value;
    bool negative = false;
    if (*value == '+' || *value == '-') negative = *value++ == '-';
    unsigned base = 10;
    bool leading_zero = *value == '0', prefix = false;
    if (leading_zero && value[1]) {
        switch (value[1]) {
            case 'x': case 'X': base = 16; prefix = true; break;
            case 'o': case 'O': base = 8; prefix = true; break;
            case 'b': case 'B': base = 2; prefix = true; break;
        }
    }
    if (prefix) {
        value += 2;
        if (*value == '_') ++value;
    }
    unsigned long long result = 0;
    unsigned long long limit = (unsigned long long)LLONG_MAX + negative;
    bool have_digit = false, underscore = false;
    for (; *value && !isspace((unsigned char)*value); ++value) {
        if (*value == '_') {
            if (!have_digit || underscore) return false;
            underscore = true; continue;
        }
        unsigned digit;
        if (*value >= '0' && *value <= '9') digit = (unsigned)(*value - '0');
        else if (*value >= 'a' && *value <= 'f') digit = (unsigned)(*value - 'a' + 10);
        else if (*value >= 'A' && *value <= 'F') digit = (unsigned)(*value - 'A' + 10);
        else return false;
        if (digit >= base || result > (limit - digit) / base) return false;
        result = result * base + digit;
        have_digit = true; underscore = false;
    }
    while (isspace((unsigned char)*value)) ++value;
    /* Match base-zero integer syntax: 00 is valid, legacy octal 012 is not. */
    if (*value || !have_digit || underscore || (leading_zero && !prefix && result)) return false;
    if (negative && result == (unsigned long long)LLONG_MAX + 1) *number = LLONG_MIN;
    else *number = negative ? -(long long)result : (long long)result;
    return true;
}
static char* normalized(const Symbol* sym, const char* value, bool enabled) {
    if (!enabled) return xstrdup(strcmp(sym->type, "bool") == 0 ? "n" : "");
    if (!value || !*value) value = sym->defval;
    if (!value) value = strcmp(sym->type, "bool") == 0 ? "n" : "";
    if (strcmp(sym->type, "bool") == 0)
        return xstrdup(!strcmp(value,"y") || !strcmp(value,"Y") || !strcmp(value,"1") ||
                       !strcmp(value,"true") || !strcmp(value,"True") ? "y" : "n");
    if (!strcmp(sym->type,"int") || !strcmp(sym->type,"hex")) {
        long long number;
        if (!parse_number(value, &number) && !parse_number(sym->defval ? sym->defval : "0", &number)) {
            fprintf(stderr, "CONFIG_%s: invalid numeric default\n", sym->name);
            exit(1);
        }
        char buf[80];
        if (!strcmp(sym->type,"int")) snprintf(buf,sizeof(buf),"%lld",number);
        else snprintf(buf,sizeof(buf),"%s0x%llx",number < 0 ? "-" : "",
                      number < 0 ? 0ULL - (unsigned long long)number : (unsigned long long)number);
        return xstrdup(buf);
    }
    return xstrdup(value);
}
void resolve(Model* model) {
    for (size_t i = 0; i < model->count; ++i) {
        Symbol* sym = &model->symbols[i];
        char* value = normalized(sym, sym->value, depends_until(model,sym->depends,i));
        free(sym->value); sym->value = value;
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


static FILE* output_file(const char* path) {
    char* copy = xstrdup(path);
    for (char* p = copy + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(copy, 0777) && errno != EEXIST) {
            fprintf(stderr, "%s: %s\n", copy, strerror(errno));
            free(copy); return NULL;
        }
        *p = '/';
    }
    free(copy);
    FILE* f = fopen(path, "w");
    if (!f) fprintf(stderr, "%s: %s\n", path, strerror(errno));
    return f;
}
static int finish(FILE* f, const char* path) {
    int failed = ferror(f);
    if (fclose(f)) failed = 1;
    if (failed) fprintf(stderr, "%s: write failed\n", path);
    return failed ? -1 : 0;
}
int write_min_config(const Model* model, const char* path, bool minimal) {
    FILE* f = output_file(path);
    if (!f) return -1;
    fprintf(f,"# %s\n# Generated by tools/kconfig.c\n\n",model->mainmenu);
    const char* menu = NULL;
    for (size_t i = 0; i < model->count; ++i) {
        const Symbol* s = &model->symbols[i];
        if (!menu || strcmp(menu,s->menu)) {
            menu = s->menu;
            if (*menu) fprintf(f,"#\n# %s\n#\n",menu);
        }
        char* def = normalized(s,NULL,eval_depends(model,s->depends));
        bool skip = minimal && !strcmp(def,s->value);
        free(def);
        if (skip) continue;
        if (!strcmp(s->type,"bool")) {
            if (bool_value(s->value)) fprintf(f,"CONFIG_%s=y\n",s->name);
            else fprintf(f,"# CONFIG_%s is not set\n",s->name);
        } else {
            fprintf(f,"CONFIG_%s=",s->name);
            if (!strcmp(s->type,"string")) fprint_quoted(f,s->value);
            else fputs(s->value,f);
            fputc('\n',f);
        }
    }
    return finish(f,path);
}
int write_config(const Model* model, const char* path) {
    return write_min_config(model,path,false);
}
int write_outputs(const Model* model, const char* mk, const char* header) {
    FILE* f = output_file(mk);
    if (!f) return -1;
    fputs("# Generated by tools/kconfig.c; do not edit.\n",f);
    for (size_t i = 0; i < model->count; ++i) {
        const Symbol* s = &model->symbols[i];
        fprintf(f,"CONFIG_%s := ",s->name);
        for (const char* p = s->value; *p; ++p) {
            if (*p == '$') fputc('$',f);
            fputc(*p,f);
        }
        fputc('\n',f);
    }
    if (finish(f,mk)) return -1;
    f = output_file(header);
    if (!f) return -1;
    fputs("/* Generated by tools/kconfig.c; do not edit. */\n#ifndef VIBEOS_GENERATED_AUTOCONF_H\n#define VIBEOS_GENERATED_AUTOCONF_H\n\n",f);
    for (size_t i = 0; i < model->count; ++i) {
        const Symbol* s = &model->symbols[i];
        if (!strcmp(s->type,"bool")) {
            if (bool_value(s->value)) fprintf(f,"#define CONFIG_%s 1\n",s->name);
            else fprintf(f,"/* #undef CONFIG_%s */\n",s->name);
        } else {
            fprintf(f,"#define CONFIG_%s ",s->name);
            if (!strcmp(s->type,"string")) fprint_quoted(f,s->value);
            else fputs(s->value,f);
            fputc('\n',f);
        }
    }
    fputs("\n#endif /* VIBEOS_GENERATED_AUTOCONF_H */\n",f);
    return finish(f,header);
}
void free_model(Model* model) {
    for (size_t i = 0; i < model->count; ++i) {
        Symbol* s = &model->symbols[i];
        free(s->name); free(s->type); free(s->prompt); free(s->defval);
        free(s->depends); free(s->menu); free(s->value);
    }
    free(model->mainmenu); free(model->symbols);
    memset(model,0,sizeof(*model));
}
