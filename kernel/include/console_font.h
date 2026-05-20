#pragma once

#include <stddef.h>
#include <stdint.h>

#define CONSOLE_FONT_MAX_WIDTH 16
#define CONSOLE_FONT_MAX_HEIGHT 36
#define CONSOLE_FONT_VARIANT_COUNT 10

typedef uint16_t console_font_row_t;

struct console_font_variant {
    uint8_t width;
    uint8_t height;
    console_font_row_t glyphs[256][CONSOLE_FONT_MAX_HEIGHT];
};

extern const struct console_font_variant g_console_font_variants[CONSOLE_FONT_VARIANT_COUNT];
