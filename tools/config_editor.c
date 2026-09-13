#define _GNU_SOURCE
#include "config_editor.h"
#include <stdlib.h>
#include <string.h>

int editor_init(ConfigEditor* e, int argc, char** argv) {
    memset(e,0,sizeof(*e));
    const char* source = "Kconfig";
    e->config = ".config"; e->mk = "build/config.mk";
    e->header = "build/include/generated/autoconf.h";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")) {
            printf("usage: %s [--kconfig PATH] [--config PATH] [--out-mk PATH] [--out-header PATH]\n",argv[0]);
            return 1;
        }
        if (i + 1 >= argc) { fprintf(stderr,"Missing option value: %s\n",argv[i]); return -1; }
        if (!strcmp(argv[i],"--kconfig")) source = argv[++i];
        else if (!strcmp(argv[i],"--config")) e->config = argv[++i];
        else if (!strcmp(argv[i],"--out-mk")) e->mk = argv[++i];
        else if (!strcmp(argv[i],"--out-header")) e->header = argv[++i];
        else { fprintf(stderr,"Unknown option: %s\n",argv[i]); return -1; }
    }
    e->model = parse_kconfig(source);
    parse_config(&e->model,e->config);
    resolve(&e->model);
    e->raw = calloc(e->model.count + 1,sizeof(*e->raw));
    e->saved = calloc(e->model.count + 1,sizeof(*e->saved));
    if (!e->raw || !e->saved) { perror("calloc"); exit(1); }
    for (size_t i = 0; i < e->model.count; ++i) {
        e->raw[i] = xstrdup(e->model.symbols[i].value);
        e->saved[i] = xstrdup(e->raw[i]);
    }
    return 0;
}
void editor_refresh(ConfigEditor* e) {
    for (size_t i = 0; i < e->model.count; ++i) set_string(&e->model.symbols[i].value,e->raw[i]);
    resolve(&e->model);
}
void editor_set(ConfigEditor* e, size_t index, const char* value) {
    set_string(&e->raw[index],value);
    editor_refresh(e);
}
bool editor_dirty(const ConfigEditor* e) {
    for (size_t i = 0; i < e->model.count; ++i)
        if (strcmp(e->raw[i],e->saved[i])) return true;
    return false;
}
bool editor_save(ConfigEditor* e) {
    editor_refresh(e);
    for (size_t i = 0; i < e->model.count; ++i) {
        const Symbol* s = &e->model.symbols[i];
        long long n;
        if (s->prompt && (!strcmp(s->type,"int") || !strcmp(s->type,"hex")) &&
            eval_depends(&e->model,s->depends) && !parse_number(e->raw[i],&n)) {
            snprintf(e->error,sizeof(e->error),"%s: enter a valid %s value.",s->prompt,s->type);
            return false;
        }
    }
    if (write_config(&e->model,e->config) || write_outputs(&e->model,e->mk,e->header)) {
        snprintf(e->error,sizeof(e->error),"Cannot write configuration outputs; check paths and permissions.");
        return false;
    }
    for (size_t i = 0; i < e->model.count; ++i) set_string(&e->saved[i],e->raw[i]);
    e->error[0] = 0;
    return true;
}
void editor_free(ConfigEditor* e) {
    for (size_t i = 0; i < e->model.count; ++i) { free(e->raw[i]); free(e->saved[i]); }
    free(e->raw); free(e->saved); free_model(&e->model);
}
char* editor_help(const Symbol* s) {
    char* result = NULL;
    if (asprintf(&result,"CONFIG_%s\nType: %s\nDefault: %s\nDepends on: %s",s->name,s->type,
        s->defval && *s->defval ? s->defval : "(none)",s->depends ? s->depends : "(none)") < 0) {
        perror("asprintf"); exit(1);
    }
    return result;
}
