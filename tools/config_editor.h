#ifndef VIBEOS_CONFIG_EDITOR_H
#define VIBEOS_CONFIG_EDITOR_H
#include "kconfig.h"
typedef struct {
    Model model;
    char **raw, **saved;
    const char *config, *mk, *header;
    char error[512];
} ConfigEditor;
int editor_init(ConfigEditor* editor, int argc, char** argv);
void editor_refresh(ConfigEditor* editor);
void editor_set(ConfigEditor* editor, size_t index, const char* value);
bool editor_dirty(const ConfigEditor* editor);
bool editor_save(ConfigEditor* editor);
void editor_free(ConfigEditor* editor);
char* editor_help(const Symbol* symbol);
#endif
