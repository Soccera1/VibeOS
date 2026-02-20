#pragma once

#include <stddef.h>

void console_init(void);
void console_set_color(unsigned fg, unsigned bg);
void console_putc(char c);
void console_write(const char* s);
void console_writen(const char* s, size_t n);
void console_printf(const char* fmt, ...);
void console_clear(void);
