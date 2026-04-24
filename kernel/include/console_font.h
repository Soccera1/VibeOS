#pragma once

#include <stdint.h>

#define CONSOLE_FONT_WIDTH 12
#define CONSOLE_FONT_HEIGHT 25

typedef uint16_t console_font_row_t;

extern const console_font_row_t g_console_font[256][CONSOLE_FONT_HEIGHT];
