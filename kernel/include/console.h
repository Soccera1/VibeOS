#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct console_framebuffer_info {
    bool present;
    uint64_t phys_addr;
    uint32_t size;
    uint32_t pitch;
    uint32_t width;
    uint32_t height;
    uint32_t text_cols;
    uint32_t text_rows;
    uint8_t bpp;
    uint8_t red_offset;
    uint8_t red_length;
    uint8_t green_offset;
    uint8_t green_length;
    uint8_t blue_offset;
    uint8_t blue_length;
    uint8_t transp_offset;
    uint8_t transp_length;
};

void console_init(uint64_t mb2_info);
void console_set_color(unsigned fg, unsigned bg);
void console_putc(char c);
void console_write(const char* s);
void console_writen(const char* s, size_t n);
void console_printf(const char* fmt, ...);
void console_clear(void);
bool console_get_framebuffer_info(struct console_framebuffer_info* out);
