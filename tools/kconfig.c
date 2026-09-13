#define _GNU_SOURCE
#include "kconfig.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static int usage(const char* name, int status) {
    fprintf(status ? stderr : stdout,
        "usage: %s COMMAND [--kconfig Kconfig] [--config .config]\n"
        "Commands: defconfig olddefconfig config oldconfig menuconfig sync savedefconfig\n"
        "sync requires --out-mk PATH --out-header PATH\n"
        "savedefconfig accepts --output PATH (default: defconfig)\n", name);
    return status;
}
int main(int argc, char** argv) {
    if (argc < 2) return usage(argv[0],2);
    if (!strcmp(argv[1],"--help") || !strcmp(argv[1],"-h")) return usage(argv[0],0);
    const char* command = argv[1];
    bool sync = !strcmp(command,"sync"), minimal = !strcmp(command,"savedefconfig");
    bool interactive = !strcmp(command,"config") || !strcmp(command,"oldconfig");
    if (!sync && !minimal && !interactive && strcmp(command,"defconfig") &&
        strcmp(command,"olddefconfig") && strcmp(command,"menuconfig")) return usage(argv[0],2);
    const char *source = "Kconfig", *config = ".config", *mk = NULL, *header = NULL, *output = "defconfig";
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")) return usage(argv[0],0);
        if (i + 1 >= argc) return usage(argv[0],2);
        if (!strcmp(argv[i],"--kconfig")) source = argv[++i];
        else if (!strcmp(argv[i],"--config")) config = argv[++i];
        else if (sync && !strcmp(argv[i],"--out-mk")) mk = argv[++i];
        else if (sync && !strcmp(argv[i],"--out-header")) header = argv[++i];
        else if (minimal && !strcmp(argv[i],"--output")) output = argv[++i];
        else return usage(argv[0],2);
    }
    if (sync && (!mk || !header)) return usage(argv[0],2);
    if (!strcmp(command,"menuconfig")) {
        const char* tool = getenv("MENUCONFIG");
        if (!tool) tool = "build/tools/menuconfig";
        execlp(tool,tool,"--kconfig",source,"--config",config,(char*)NULL);
        perror(tool); return 1;
    }
    Model model = parse_kconfig(source);
    if (strcmp(command,"defconfig")) parse_config(&model,config);
    bool* present = calloc(model.count ? model.count : 1,sizeof(*present));
    if (!present) { perror("calloc"); free_model(&model); return 1; }
    for (size_t i = 0; i < model.count; ++i) present[i] = model.symbols[i].value != NULL;
    resolve(&model);
    int result = 0;
    if (interactive) {
        char* line = NULL;
        size_t capacity = 0;
        for (size_t i = 0; i < model.count; ++i) {
            Symbol* s = &model.symbols[i];
            if (!strcmp(command,"oldconfig") && present[i]) continue;
            bool boolean = !strcmp(s->type,"bool");
            if (boolean) printf("%s (%s) ",s->prompt ? s->prompt : s->name,bool_value(s->value) ? "Y/n" : "y/N");
            else printf("%s [%s] ",s->prompt ? s->prompt : s->name,s->value);
            fflush(stdout);
            if (getline(&line,&capacity,stdin) < 0) {
                fprintf(stderr,"Configuration input ended; changes were not saved.\n");
                result = 1; break;
            }
            char* answer = trim(line);
            if (boolean) {
                if (!strcasecmp(answer,"y") || !strcasecmp(answer,"yes")) set_string(&s->value,"y");
                else if (!strcasecmp(answer,"n") || !strcasecmp(answer,"no")) set_string(&s->value,"n");
            } else if (*answer) set_string(&s->value,answer);
        }
        free(line);
        resolve(&model);
    }
    if (!result) result = write_min_config(&model,minimal ? output : config,minimal) != 0;
    if (!result && sync) result = write_outputs(&model,mk,header) != 0;
    free(present); free_model(&model);
    return result;
}
