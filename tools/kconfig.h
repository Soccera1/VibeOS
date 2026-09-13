#ifndef VIBEOS_KCONFIG_H
#define VIBEOS_KCONFIG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
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


char* xstrdup(const char* s);
char* trim(char* s);
void set_string(char** dst, const char* value);
Model parse_kconfig(const char* path);
void parse_config(Model* model, const char* path);
int find_symbol(const Model* model, const char* name);
bool bool_value(const char* value);
bool eval_depends(const Model* model, const char* expr);
/* Numeric options use signed 64-bit values and base-zero integer syntax. */
bool parse_number(const char* value, long long* number);
/* Resolve in declaration order, replacing input values with normalized values. */
void resolve(Model* model);
int write_config(const Model* model, const char* path);
int write_min_config(const Model* model, const char* path, bool minimal);
int write_outputs(const Model* model, const char* mk, const char* header);
void free_model(Model* model);
#endif
