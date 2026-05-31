#include "console.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "console_font.h"
#include "input.h"
#include "io.h"
#include "keyboard.h"
#include "multiboot2.h"
#include "serial.h"
#include "string.h"

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define FRAMEBUFFER_TEXT_ROWS VGA_HEIGHT
#define FONT_NATURAL_WIDTH 12u
#define FONT_NATURAL_HEIGHT 25u
#define FB_MAX_COLS 512
#define FB_MAX_ROWS 256
#define TAB_WIDTH 8
#define TEXT_CELL_CAPACITY (FB_MAX_COLS * FB_MAX_ROWS)
#define TAB_STOP_CAPACITY FB_MAX_COLS
#define CELL_FLAG_UNDERLINE 0x01u
#define VGA_CRTC_INDEX 0x3D4
#define VGA_CRTC_DATA 0x3D5
#define VGA_CRTC_CURSOR_START 0x0A
#define VGA_CRTC_CURSOR_POS_LO 0x0F
#define VGA_CRTC_CURSOR_POS_HI 0x0E
#define SOFT_CURSOR_HEIGHT 3u

static volatile uint16_t* const vga_hw = (volatile uint16_t*)0xB8000;
static uint16_t text_cells[TEXT_CELL_CAPACITY];
static uint8_t text_cell_flags[TEXT_CELL_CAPACITY];
static uint16_t main_vga[TEXT_CELL_CAPACITY];
static uint8_t main_vga_flags[TEXT_CELL_CAPACITY];
static uint16_t resize_cells[TEXT_CELL_CAPACITY];
static uint8_t resize_cell_flags[TEXT_CELL_CAPACITY];
static size_t text_cols = VGA_WIDTH;
static size_t text_rows = VGA_HEIGHT;
static size_t cursor_row;
static size_t cursor_col;
static uint8_t color = 0x07;
static uint8_t base_fg = 0x07;
static uint8_t base_bg;
static bool sgr_bold;
static bool sgr_reverse;
static bool sgr_underline;
static bool sgr_blink;
static bool sgr_invisible;
static uint8_t saved_color;
static size_t saved_cursor_row;
static size_t saved_cursor_col;
static uint8_t saved_base_fg;
static uint8_t saved_base_bg;
static bool saved_sgr_bold;
static bool saved_sgr_reverse;
static bool saved_sgr_underline;
static bool saved_sgr_blink;
static bool saved_sgr_invisible;
static bool alt_mode_active;
static size_t scroll_top;
static size_t scroll_bottom = VGA_HEIGHT - 1;
static bool g1_charset_graphics;
static bool shift_out_active;
static bool saved_g1_charset_graphics;
static bool saved_shift_out_active;
static uint8_t ansi_state;  // 0=none, 1=ESC, 2=CSI, 3=ESC ), 4=OSC, 5=charset designator
static char ansi_buf[32];
static size_t ansi_len;
static struct console_framebuffer_info g_fb_info;
static volatile uint8_t* g_fb_base;
static size_t g_fb_origin_x;
static size_t g_fb_origin_y;
static size_t g_fb_cell_width = 12u;
static size_t g_fb_cell_height = 25u;
static const struct console_font_variant* g_fb_font = &g_console_font_variants[0];
static uint32_t g_fb_palette[16];
static console_framebuffer_flush_fn g_fb_flush_callback;
static bool g_fb_bulk_present;
static size_t g_fb_bulk_depth;
static bool g_fb_bulk_dirty;
static size_t g_fb_dirty_x0;
static size_t g_fb_dirty_y0;
static size_t g_fb_dirty_x1;
static size_t g_fb_dirty_y1;
static bool cursor_visible = true;
static bool soft_cursor_drawn;
static size_t soft_cursor_row;
static size_t soft_cursor_col;
static bool tab_stops[TAB_STOP_CAPACITY];
static uint8_t last_printed_char = ' ';

static uint8_t current_cell_flags(void) {
    uint8_t flags = 0;
    if (sgr_underline) {
        flags |= CELL_FLAG_UNDERLINE;
    }
    return flags;
}

static const uint8_t g_vga_palette_rgb[16][3] = {
    {0x00, 0x00, 0x00}, {0x00, 0x00, 0xaa}, {0x00, 0xaa, 0x00}, {0x00, 0xaa, 0xaa},
    {0xaa, 0x00, 0x00}, {0xaa, 0x00, 0xaa}, {0xaa, 0x55, 0x00}, {0xaa, 0xaa, 0xaa},
    {0x55, 0x55, 0x55}, {0x55, 0x55, 0xff}, {0x55, 0xff, 0x55}, {0x55, 0xff, 0xff},
    {0xff, 0x55, 0x55}, {0xff, 0x55, 0xff}, {0xff, 0xff, 0x55}, {0xff, 0xff, 0xff},
};

static uint16_t blank_cell(void) {
    return ((uint16_t)color << 8) | ' ';
}

static bool framebuffer_active(void) {
    return g_fb_info.present && g_fb_base != NULL;
}

static size_t cell_index(size_t row, size_t col) {
    return row * text_cols + col;
}

static size_t cell_count(void) {
    return text_cols * text_rows;
}

static void clamp_cursor(void);

static size_t max_size(size_t a, size_t b) {
    return (a > b) ? a : b;
}

static void set_text_geometry(size_t cols, size_t rows) {
    if (cols == 0u || rows == 0u) {
        cols = VGA_WIDTH;
        rows = VGA_HEIGHT;
    }
    if (cols > FB_MAX_COLS) {
        cols = FB_MAX_COLS;
    }
    if (rows > FB_MAX_ROWS) {
        rows = FB_MAX_ROWS;
    }
    text_cols = cols;
    text_rows = rows;
    scroll_top = 0;
    scroll_bottom = text_rows - 1u;
}

static void resize_cell_buffer(uint16_t* cells, uint8_t* flags, size_t old_cols, size_t old_rows, size_t new_cols,
                               size_t new_rows) {
    uint16_t blank = blank_cell();
    size_t copy_cols = (old_cols < new_cols) ? old_cols : new_cols;
    size_t copy_rows = (old_rows < new_rows) ? old_rows : new_rows;

    for (size_t row = 0; row < new_rows; ++row) {
        for (size_t col = 0; col < new_cols; ++col) {
            size_t dst = row * new_cols + col;
            if (row < copy_rows && col < copy_cols) {
                size_t src = row * old_cols + col;
                resize_cells[dst] = cells[src];
                resize_cell_flags[dst] = flags[src];
            } else {
                resize_cells[dst] = blank;
                resize_cell_flags[dst] = 0u;
            }
        }
    }

    for (size_t i = 0; i < new_cols * new_rows; ++i) {
        cells[i] = resize_cells[i];
        flags[i] = resize_cell_flags[i];
    }
}

static void resize_text_geometry(size_t cols, size_t rows) {
    size_t old_cols = text_cols;
    size_t old_rows = text_rows;

    if (cols == 0u || rows == 0u) {
        cols = VGA_WIDTH;
        rows = VGA_HEIGHT;
    }
    if (cols > FB_MAX_COLS) {
        cols = FB_MAX_COLS;
    }
    if (rows > FB_MAX_ROWS) {
        rows = FB_MAX_ROWS;
    }
    if (cols == old_cols && rows == old_rows) {
        return;
    }

    resize_cell_buffer(text_cells, text_cell_flags, old_cols, old_rows, cols, rows);
    resize_cell_buffer(main_vga, main_vga_flags, old_cols, old_rows, cols, rows);
    set_text_geometry(cols, rows);
    clamp_cursor();
}

static size_t framebuffer_text_cols_for_size(uint32_t width, uint32_t height) {
    if (height == 0u) {
        return VGA_WIDTH;
    }

    size_t cell_height = max_size((size_t)height / FRAMEBUFFER_TEXT_ROWS, 1u);
    size_t cell_width = max_size((cell_height * FONT_NATURAL_WIDTH + FONT_NATURAL_HEIGHT / 2u) / FONT_NATURAL_HEIGHT, 1u);
    size_t cols = (size_t)width / cell_width;
    if (cols == 0u) {
        cols = 1u;
    }
    return cols;
}

static const struct console_font_variant* choose_framebuffer_font(size_t cell_width, size_t cell_height) {
    const struct console_font_variant* best = &g_console_font_variants[0];
    size_t best_score = (size_t)-1;

    for (size_t i = 0; i < CONSOLE_FONT_VARIANT_COUNT; ++i) {
        const struct console_font_variant* candidate = &g_console_font_variants[i];
        size_t width_delta = (candidate->width > cell_width) ? candidate->width - cell_width : cell_width - candidate->width;
        size_t height_delta = (candidate->height > cell_height) ? candidate->height - cell_height : cell_height - candidate->height;
        size_t upsample_penalty = (candidate->width < cell_width ? cell_width - candidate->width : 0u) +
                                  (candidate->height < cell_height ? cell_height - candidate->height : 0u);
        size_t downsample_penalty = (candidate->width > cell_width ? candidate->width - cell_width : 0u) * 3u +
                                    (candidate->height > cell_height ? candidate->height - cell_height : 0u) * 3u;
        size_t score = width_delta * 64u + height_delta * 32u + upsample_penalty + downsample_penalty;
        if (score < best_score) {
            best = candidate;
            best_score = score;
        }
    }

    return best;
}

static void update_framebuffer_text_metrics(void) {
    if (!framebuffer_active()) {
        g_fb_origin_x = 0;
        g_fb_origin_y = 0;
        g_fb_cell_width = FONT_NATURAL_WIDTH;
        g_fb_cell_height = FONT_NATURAL_HEIGHT;
        g_fb_font = &g_console_font_variants[0];
        return;
    }

    g_fb_cell_height = max_size(g_fb_info.height / text_rows, 1u);
    g_fb_cell_width = max_size(g_fb_info.width / text_cols, 1u);
    g_fb_font = choose_framebuffer_font(g_fb_cell_width, g_fb_cell_height);
    g_fb_origin_x = (g_fb_info.width - text_cols * g_fb_cell_width) / 2u;
    g_fb_origin_y = (g_fb_info.height - text_rows * g_fb_cell_height) / 2u;
}

static void framebuffer_flush_rect(size_t x, size_t y, size_t width, size_t height) {
    if (g_fb_flush_callback == NULL || !framebuffer_active() || width == 0u || height == 0u) {
        return;
    }
    if (x >= g_fb_info.width || y >= g_fb_info.height) {
        return;
    }
    if (width > g_fb_info.width - x) {
        width = g_fb_info.width - x;
    }
    if (height > g_fb_info.height - y) {
        height = g_fb_info.height - y;
    }
    if (g_fb_bulk_depth != 0u) {
        size_t x1 = x + width;
        size_t y1 = y + height;
        if (!g_fb_bulk_dirty) {
            g_fb_dirty_x0 = x;
            g_fb_dirty_y0 = y;
            g_fb_dirty_x1 = x1;
            g_fb_dirty_y1 = y1;
            g_fb_bulk_dirty = true;
            return;
        }
        if (x < g_fb_dirty_x0) {
            g_fb_dirty_x0 = x;
        }
        if (y < g_fb_dirty_y0) {
            g_fb_dirty_y0 = y;
        }
        if (x1 > g_fb_dirty_x1) {
            g_fb_dirty_x1 = x1;
        }
        if (y1 > g_fb_dirty_y1) {
            g_fb_dirty_y1 = y1;
        }
        return;
    }
    g_fb_flush_callback((uint32_t)x, (uint32_t)y, (uint32_t)width, (uint32_t)height);
}

static void framebuffer_begin_bulk(void) {
    if (g_fb_flush_callback == NULL || !framebuffer_active()) {
        return;
    }
    if (g_fb_bulk_depth == 0u) {
        g_fb_bulk_dirty = false;
    }
    ++g_fb_bulk_depth;
}

static void framebuffer_end_bulk(void) {
    if (g_fb_bulk_depth == 0u) {
        return;
    }
    --g_fb_bulk_depth;
    if (g_fb_bulk_depth != 0u) {
        return;
    }
    if (!g_fb_bulk_dirty) {
        return;
    }
    size_t x = g_fb_dirty_x0;
    size_t y = g_fb_dirty_y0;
    size_t width = g_fb_dirty_x1 - g_fb_dirty_x0;
    size_t height = g_fb_dirty_y1 - g_fb_dirty_y0;
    g_fb_bulk_dirty = false;
    framebuffer_flush_rect(x, y, width, height);
}

static uint32_t scale_channel(uint8_t value, uint8_t bits) {
    if (bits == 0u) {
        return 0u;
    }

    uint32_t max_value = (1u << bits) - 1u;
    return ((uint32_t)value * max_value + 127u) / 255u;
}

static uint32_t pack_fb_color(uint8_t r, uint8_t g, uint8_t b) {
    return (scale_channel(r, g_fb_info.red_length) << g_fb_info.red_offset) |
           (scale_channel(g, g_fb_info.green_length) << g_fb_info.green_offset) |
           (scale_channel(b, g_fb_info.blue_length) << g_fb_info.blue_offset);
}

static void fb_store_pixel(size_t x, size_t y, uint32_t pixel) {
    if (!framebuffer_active() || x >= g_fb_info.width || y >= g_fb_info.height) {
        return;
    }

    uint8_t bytes_per_pixel = (uint8_t)((g_fb_info.bpp + 7u) / 8u);
    volatile uint8_t* dst = g_fb_base + y * g_fb_info.pitch + x * bytes_per_pixel;
    if (bytes_per_pixel == 4u) {
        *(volatile uint32_t*)(uintptr_t)dst = pixel;
    } else if (bytes_per_pixel == 3u) {
        dst[0] = (uint8_t)(pixel & 0xffu);
        dst[1] = (uint8_t)((pixel >> 8) & 0xffu);
        dst[2] = (uint8_t)((pixel >> 16) & 0xffu);
    } else if (bytes_per_pixel == 2u) {
        *(volatile uint16_t*)(uintptr_t)dst = (uint16_t)pixel;
    } else if (bytes_per_pixel == 1u) {
        dst[0] = (uint8_t)pixel;
    }
}

static void fb_fill_rect(size_t x, size_t y, size_t width, size_t height, uint32_t pixel) {
    for (size_t py = 0; py < height; ++py) {
        for (size_t px = 0; px < width; ++px) {
            fb_store_pixel(x + px, y + py, pixel);
        }
    }
}

static void draw_framebuffer_cell(size_t row, size_t col, uint16_t cell, uint8_t flags, bool cursor_overlay) {
    uint8_t ch = (uint8_t)(cell & 0xffu);
    uint8_t attr = (uint8_t)(cell >> 8);
    uint32_t fg = g_fb_palette[attr & 0x0fu];
    uint32_t bg = g_fb_palette[(attr >> 4) & 0x07u];
    size_t x0 = g_fb_origin_x + col * g_fb_cell_width;
    size_t y0 = g_fb_origin_y + row * g_fb_cell_height;

    for (size_t py = 0; py < g_fb_cell_height; ++py) {
        size_t glyph_row = (py * g_fb_font->height) / g_fb_cell_height;
        console_font_row_t bits = g_fb_font->glyphs[ch][glyph_row];
        for (size_t px = 0; px < g_fb_cell_width; ++px) {
            size_t glyph_col = (px * g_fb_font->width) / g_fb_cell_width;
            console_font_row_t mask = (console_font_row_t)(1u << (g_fb_font->width - 1u - glyph_col));
            uint32_t pixel = ((bits & mask) != 0u) ? fg : bg;
            if ((flags & CELL_FLAG_UNDERLINE) != 0u && glyph_row + 2u >= g_fb_font->height) {
                pixel = fg;
            }
            if (cursor_overlay &&
                py + max_size((SOFT_CURSOR_HEIGHT * g_fb_cell_height) / g_fb_font->height, 1u) >= g_fb_cell_height) {
                pixel = fg;
            }
            fb_store_pixel(x0 + px, y0 + py, pixel);
        }
    }
}

static void draw_cell(size_t row, size_t col, uint16_t cell) {
    if (!framebuffer_active()) {
        vga_hw[cell_index(row, col)] = cell;
        return;
    }

    draw_framebuffer_cell(row, col, cell, text_cell_flags[cell_index(row, col)], false);
    if (!g_fb_bulk_present) {
        framebuffer_flush_rect(g_fb_origin_x + col * g_fb_cell_width, g_fb_origin_y + row * g_fb_cell_height,
                               g_fb_cell_width, g_fb_cell_height);
    }
}

static void restore_soft_cursor(void) {
    if (!soft_cursor_drawn) {
        return;
    }

    draw_cell(soft_cursor_row, soft_cursor_col, text_cells[cell_index(soft_cursor_row, soft_cursor_col)]);
    soft_cursor_drawn = false;
}

static void draw_soft_cursor(void) {
    if (!framebuffer_active() || !cursor_visible) {
        return;
    }

    soft_cursor_row = cursor_row;
    soft_cursor_col = cursor_col;
    draw_framebuffer_cell(cursor_row, cursor_col, text_cells[cell_index(cursor_row, cursor_col)],
                          text_cell_flags[cell_index(cursor_row, cursor_col)], true);
    soft_cursor_drawn = true;
    framebuffer_flush_rect(g_fb_origin_x + cursor_col * g_fb_cell_width, g_fb_origin_y + cursor_row * g_fb_cell_height,
                           g_fb_cell_width, g_fb_cell_height);
}

static void present_row_range(size_t row, size_t start_col, size_t end_col) {
    if (row >= text_rows || start_col >= text_cols) {
        return;
    }
    if (end_col > text_cols) {
        end_col = text_cols;
    }

    for (size_t x = start_col; x < end_col; ++x) {
        draw_cell(row, x, text_cells[cell_index(row, x)]);
    }
}

static void present_rows(size_t start_row, size_t end_row) {
    if (end_row > text_rows) {
        end_row = text_rows;
    }
    for (size_t row = start_row; row < end_row; ++row) {
        present_row_range(row, 0, text_cols);
    }
}

static void present_all(void) {
    if (framebuffer_active()) {
        fb_fill_rect(0, 0, g_fb_info.width, g_fb_info.height, g_fb_palette[0]);
    }
    g_fb_bulk_present = true;
    present_rows(0, text_rows);
    g_fb_bulk_present = false;
    framebuffer_flush_rect(0, 0, g_fb_info.width, g_fb_info.height);
}

static void apply_text_attributes(void) {
    uint8_t fg = (uint8_t)(base_fg & 0x07u);
    uint8_t bg = (uint8_t)(base_bg & 0x07u);

    if (sgr_bold) {
        fg = (uint8_t)(fg | 0x08u);
    }

    if (sgr_reverse) {
        uint8_t rev_fg = bg;
        uint8_t rev_bg = (uint8_t)(fg & 0x07u);
        fg = rev_fg;
        bg = rev_bg;
    }

    if (sgr_invisible) {
        fg = bg;
    }

    color = (uint8_t)((bg << 4) | (fg & 0x0Fu));
    if (sgr_blink) {
        color = (uint8_t)(color | 0x80u);
    }
}

static void reset_text_attributes(void) {
    base_fg = 0x07u;
    base_bg = 0x00u;
    sgr_bold = false;
    sgr_reverse = false;
    sgr_underline = false;
    sgr_blink = false;
    sgr_invisible = false;
    apply_text_attributes();
}

static void clear_row_range(size_t row, size_t start_col, size_t end_col) {
    if (row >= text_rows || start_col >= text_cols) {
        return;
    }

    if (end_col > text_cols) {
        end_col = text_cols;
    }

    for (size_t x = start_col; x < end_col; ++x) {
        text_cells[cell_index(row, x)] = blank_cell();
        text_cell_flags[cell_index(row, x)] = 0;
    }
    present_row_range(row, start_col, end_col);
}

static void clear_screen_entire(void) {
    uint16_t blank = blank_cell();
    for (size_t i = 0; i < cell_count(); ++i) {
        text_cells[i] = blank;
        text_cell_flags[i] = 0;
    }
    present_all();
}

static void scroll_up_region(size_t top, size_t bottom, size_t lines) {
    if (top >= text_rows || bottom >= text_rows || top > bottom) {
        return;
    }

    size_t height = bottom - top + 1u;
    if (lines >= height) {
        for (size_t y = top; y <= bottom; ++y) {
            clear_row_range(y, 0, text_cols);
        }
        return;
    }

    memmove(&text_cells[cell_index(top, 0)], &text_cells[cell_index(top + lines, 0)],
            (height - lines) * text_cols * sizeof(text_cells[0]));
    memmove(&text_cell_flags[cell_index(top, 0)], &text_cell_flags[cell_index(top + lines, 0)],
            (height - lines) * text_cols * sizeof(text_cell_flags[0]));
    for (size_t y = bottom + 1u - lines; y <= bottom; ++y) {
        for (size_t x = 0; x < text_cols; ++x) {
            text_cells[cell_index(y, x)] = blank_cell();
            text_cell_flags[cell_index(y, x)] = 0;
        }
    }
    present_rows(top, bottom + 1u);
}

static void scroll_down_region(size_t top, size_t bottom, size_t lines) {
    if (top >= text_rows || bottom >= text_rows || top > bottom) {
        return;
    }

    size_t height = bottom - top + 1u;
    if (lines >= height) {
        for (size_t y = top; y <= bottom; ++y) {
            clear_row_range(y, 0, text_cols);
        }
        return;
    }

    memmove(&text_cells[cell_index(top + lines, 0)], &text_cells[cell_index(top, 0)],
            (height - lines) * text_cols * sizeof(text_cells[0]));
    memmove(&text_cell_flags[cell_index(top + lines, 0)], &text_cell_flags[cell_index(top, 0)],
            (height - lines) * text_cols * sizeof(text_cell_flags[0]));
    for (size_t y = top; y < top + lines; ++y) {
        for (size_t x = 0; x < text_cols; ++x) {
            text_cells[cell_index(y, x)] = blank_cell();
            text_cell_flags[cell_index(y, x)] = 0;
        }
    }
    present_rows(top, bottom + 1u);
}

static void clamp_cursor(void) {
    if (cursor_row >= text_rows) {
        cursor_row = text_rows - 1;
    }
    if (cursor_col >= text_cols) {
        cursor_col = text_cols - 1;
    }
}

static void set_vga_cursor_enabled(bool enabled) {
    outb(VGA_CRTC_INDEX, VGA_CRTC_CURSOR_START);
    uint8_t cursor_start = inb(VGA_CRTC_DATA);
    if (enabled) {
        cursor_start &= (uint8_t)~0x20u;
    } else {
        cursor_start |= 0x20u;
    }
    outb(VGA_CRTC_INDEX, VGA_CRTC_CURSOR_START);
    outb(VGA_CRTC_DATA, cursor_start);
}

static void update_hw_cursor(void) {
    clamp_cursor();
    if (framebuffer_active()) {
        restore_soft_cursor();
        draw_soft_cursor();
        return;
    }

    soft_cursor_drawn = false;
    set_vga_cursor_enabled(cursor_visible);
    if (!cursor_visible) {
        return;
    }

    size_t row = cursor_row;
    size_t col = cursor_col;
    uint16_t pos = (uint16_t)(row * text_cols + col);
    outb(VGA_CRTC_INDEX, VGA_CRTC_CURSOR_POS_LO);
    outb(VGA_CRTC_DATA, (uint8_t)(pos & 0xFFu));
    outb(VGA_CRTC_INDEX, VGA_CRTC_CURSOR_POS_HI);
    outb(VGA_CRTC_DATA, (uint8_t)((pos >> 8) & 0xFFu));
}

static void clear_line_from_cursor(void) {
    clamp_cursor();
    clear_row_range(cursor_row, cursor_col, text_cols);
}

static void clear_screen_from_cursor(void) {
    clamp_cursor();
    clear_line_from_cursor();

    for (size_t y = cursor_row + 1; y < text_rows; ++y) {
        clear_row_range(y, 0, text_cols);
    }
}

static size_t parse_ansi_params(unsigned* params, size_t max_params, bool* private_mode) {
    size_t count = 0;
    size_t i = 0;
    const size_t seq_len = (ansi_len > 0) ? (ansi_len - 1) : 0;

    if (private_mode != NULL) {
        *private_mode = false;
    }

    if (seq_len > 0 && ansi_buf[0] == '?') {
        if (private_mode != NULL) {
            *private_mode = true;
        }
        i = 1;
    }

    while (i < seq_len) {
        unsigned value = 0u;
        bool have_value = false;

        while (i < seq_len && ansi_buf[i] != ';') {
            char c = ansi_buf[i++];
            if (c >= '0' && c <= '9') {
                have_value = true;
                value = value * 10u + (unsigned)(c - '0');
                continue;
            }
            i = seq_len;
            break;
        }

        if (count < max_params) {
            params[count] = have_value ? value : 0u;
        }
        ++count;

        if (i >= seq_len) {
            break;
        }

        ++i;
        if (i == seq_len) {
            if (count < max_params) {
                params[count] = 0u;
            }
            ++count;
            break;
        }
    }

    return count;
}

static unsigned ansi_param_or_default(const unsigned* params, size_t count, size_t idx, unsigned default_value) {
    if (idx < count) {
        return params[idx];
    }
    return default_value;
}

static void move_cursor_to(unsigned row_1based, unsigned col_1based) {
    if (row_1based == 0u) {
        row_1based = 1u;
    }
    if (col_1based == 0u) {
        col_1based = 1u;
    }

    cursor_row = (size_t)(row_1based - 1u);
    cursor_col = (size_t)(col_1based - 1u);
    clamp_cursor();
}

static void move_cursor_relative(int row_delta, int col_delta) {
    int row = (int)cursor_row + row_delta;
    int col = (int)cursor_col + col_delta;

    if (row < 0) {
        row = 0;
    } else if (row >= (int)text_rows) {
        row = (int)text_rows - 1;
    }

    if (col < 0) {
        col = 0;
    } else if (col >= (int)text_cols) {
        col = (int)text_cols - 1;
    }

    cursor_row = (size_t)row;
    cursor_col = (size_t)col;
}

static void clear_entire_line(void) {
    clamp_cursor();
    clear_row_range(cursor_row, 0, text_cols);
}

static void clear_line_to_cursor(void) {
    clamp_cursor();
    clear_row_range(cursor_row, 0, cursor_col + 1u);
}

static void clear_screen_to_cursor(void) {
    clamp_cursor();

    for (size_t y = 0; y < cursor_row; ++y) {
        clear_row_range(y, 0, text_cols);
    }

    clear_row_range(cursor_row, 0, cursor_col + 1u);
}

static void insert_blank_chars(size_t count) {
    clamp_cursor();
    if (count == 0 || cursor_col >= text_cols) {
        return;
    }
    if (count > text_cols - cursor_col) {
        count = text_cols - cursor_col;
    }

    size_t row_base = cursor_row * text_cols;
    memmove(&text_cells[row_base + cursor_col + count], &text_cells[row_base + cursor_col],
            (text_cols - cursor_col - count) * sizeof(text_cells[0]));
    memmove(&text_cell_flags[row_base + cursor_col + count], &text_cell_flags[row_base + cursor_col],
            (text_cols - cursor_col - count) * sizeof(text_cell_flags[0]));
    for (size_t x = cursor_col; x < cursor_col + count; ++x) {
        text_cells[row_base + x] = blank_cell();
        text_cell_flags[row_base + x] = 0;
    }
    present_row_range(cursor_row, cursor_col, text_cols);
}

static void delete_chars(size_t count) {
    clamp_cursor();
    if (count == 0 || cursor_col >= text_cols) {
        return;
    }
    if (count > text_cols - cursor_col) {
        count = text_cols - cursor_col;
    }

    size_t row_base = cursor_row * text_cols;
    memmove(&text_cells[row_base + cursor_col], &text_cells[row_base + cursor_col + count],
            (text_cols - cursor_col - count) * sizeof(text_cells[0]));
    memmove(&text_cell_flags[row_base + cursor_col], &text_cell_flags[row_base + cursor_col + count],
            (text_cols - cursor_col - count) * sizeof(text_cell_flags[0]));
    for (size_t x = text_cols - count; x < text_cols; ++x) {
        text_cells[row_base + x] = blank_cell();
        text_cell_flags[row_base + x] = 0;
    }
    present_row_range(cursor_row, cursor_col, text_cols);
}

static void erase_chars(size_t count) {
    clamp_cursor();
    if (count == 0) {
        return;
    }
    if (count > text_cols - cursor_col) {
        count = text_cols - cursor_col;
    }
    clear_row_range(cursor_row, cursor_col, cursor_col + count);
}

static void linefeed(void);
static uint8_t translate_graphics_char(uint8_t c);

static void cursor_tab_forward(size_t count) {
    clamp_cursor();
    if (count == 0) {
        count = 1;
    }

    while (count-- > 0) {
        size_t next = cursor_col + 1u;
        while (next < text_cols && !tab_stops[next]) {
            ++next;
        }
        cursor_col = (next < text_cols) ? next : (text_cols - 1u);
    }
}

static void cursor_tab_backward(size_t count) {
    clamp_cursor();
    if (count == 0) {
        count = 1;
    }

    while (count-- > 0) {
        if (cursor_col == 0) {
            return;
        }
        size_t prev = cursor_col - 1u;
        while (prev > 0 && !tab_stops[prev]) {
            --prev;
        }
        cursor_col = tab_stops[prev] ? prev : 0;
    }
}

static void set_tab_stop(void) {
    clamp_cursor();
    if (cursor_col < TAB_STOP_CAPACITY) {
        tab_stops[cursor_col] = true;
    }
}

static void clear_tab_stop_at_cursor(void) {
    clamp_cursor();
    if (cursor_col < TAB_STOP_CAPACITY) {
        tab_stops[cursor_col] = false;
    }
}

static void clear_all_tab_stops(void) {
    memset(tab_stops, 0, sizeof(tab_stops));
}

static void reset_tab_stops(void) {
    clear_all_tab_stops();
    for (size_t col = TAB_WIDTH; col < TAB_STOP_CAPACITY; col += TAB_WIDTH) {
        tab_stops[col] = true;
    }
}

static void repeat_last_printed_char(size_t count) {
    if (count == 0) {
        count = 1;
    }

    for (size_t i = 0; i < count; ++i) {
        uint8_t ch = translate_graphics_char(last_printed_char);
        clamp_cursor();
        serial_putc((char)last_printed_char);
        text_cells[cell_index(cursor_row, cursor_col)] = ((uint16_t)color << 8) | ch;
        text_cell_flags[cell_index(cursor_row, cursor_col)] = current_cell_flags();
        present_row_range(cursor_row, cursor_col, cursor_col + 1u);
        ++cursor_col;
        if (cursor_col >= text_cols) {
            cursor_col = 0;
            linefeed();
        }
    }
}

static void enqueue_decimal(unsigned value) {
    char buf[10];
    size_t idx = 0;

    if (value == 0u) {
        input_enqueue_response_char('0');
        return;
    }

    while (value != 0u && idx < sizeof(buf)) {
        buf[idx++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    while (idx > 0) {
        input_enqueue_response_char(buf[--idx]);
    }
}

static void enqueue_cursor_position_report(void) {
    input_enqueue_response_string("\x1b[");
    enqueue_decimal((unsigned)(cursor_row + 1u));
    input_enqueue_response_char(';');
    enqueue_decimal((unsigned)(cursor_col + 1u));
    input_enqueue_response_char('R');
}

static void insert_lines(size_t count) {
    clamp_cursor();
    if (cursor_row < scroll_top || cursor_row > scroll_bottom || count == 0) {
        return;
    }
    scroll_down_region(cursor_row, scroll_bottom, count);
}

static void delete_lines(size_t count) {
    clamp_cursor();
    if (cursor_row < scroll_top || cursor_row > scroll_bottom || count == 0) {
        return;
    }
    scroll_up_region(cursor_row, scroll_bottom, count);
}

static void linefeed(void) {
    clamp_cursor();

    if (cursor_row >= scroll_top && cursor_row <= scroll_bottom) {
        if (cursor_row == scroll_bottom) {
            scroll_up_region(scroll_top, scroll_bottom, 1u);
            return;
        }
    } else if (cursor_row == text_rows - 1u) {
        scroll_up_region(0, text_rows - 1u, 1u);
        return;
    }

    ++cursor_row;
    clamp_cursor();
}

static void reverse_index(void) {
    clamp_cursor();

    if (cursor_row >= scroll_top && cursor_row <= scroll_bottom) {
        if (cursor_row == scroll_top) {
            scroll_down_region(scroll_top, scroll_bottom, 1u);
            return;
        }
    } else if (cursor_row == 0u) {
        scroll_down_region(0, text_rows - 1u, 1u);
        return;
    }

    if (cursor_row > 0u) {
        --cursor_row;
    }
}

static void set_scroll_region(unsigned top_1based, unsigned bottom_1based) {
    if (top_1based == 0u) {
        top_1based = 1u;
    }
    if (bottom_1based == 0u) {
        bottom_1based = (unsigned)text_rows;
    }
    if (top_1based > text_rows || bottom_1based > text_rows || top_1based >= bottom_1based) {
        scroll_top = 0;
        scroll_bottom = text_rows - 1u;
    } else {
        scroll_top = (size_t)(top_1based - 1u);
        scroll_bottom = (size_t)(bottom_1based - 1u);
    }
    cursor_row = 0;
    cursor_col = 0;
}

static uint8_t translate_graphics_char(uint8_t c) {
    if (!shift_out_active || !g1_charset_graphics) {
        return c;
    }

    switch (c) {
        case 'j':
            return 217u;
        case 'k':
            return 191u;
        case 'l':
            return 218u;
        case 'm':
            return 192u;
        case 'n':
            return 197u;
        case 'q':
            return 196u;
        case 't':
            return 195u;
        case 'u':
            return 180u;
        case 'v':
            return 193u;
        case 'w':
            return 194u;
        case 'x':
            return 179u;
        default:
            return c;
    }
}

static void reset_console_state(void) {
    ansi_state = 0;
    ansi_len = 0;
    scroll_top = 0;
    scroll_bottom = text_rows - 1u;
    g1_charset_graphics = false;
    shift_out_active = false;
    keyboard_set_application_cursor_keys(false);
    cursor_visible = true;
    soft_cursor_drawn = false;
    reset_tab_stops();
    reset_text_attributes();
}

static bool setup_framebuffer_info(const struct console_framebuffer_info* info, console_framebuffer_flush_fn flush_callback) {
    bool had_framebuffer = framebuffer_active();
    memset(&g_fb_info, 0, sizeof(g_fb_info));
    g_fb_base = NULL;
    g_fb_origin_x = 0;
    g_fb_origin_y = 0;
    g_fb_cell_width = FONT_NATURAL_WIDTH;
    g_fb_cell_height = FONT_NATURAL_HEIGHT;
    g_fb_font = &g_console_font_variants[0];
    g_fb_flush_callback = NULL;

    if (info == NULL || !info->present || info->phys_addr == 0 || info->phys_addr >= (1ull << 32) ||
        info->width < VGA_WIDTH || info->height < VGA_HEIGHT) {
        set_text_geometry(VGA_WIDTH, VGA_HEIGHT);
        return false;
    }
    if (info->bpp != 15u && info->bpp != 16u && info->bpp != 24u && info->bpp != 32u) {
        if (!had_framebuffer) {
            set_text_geometry(VGA_WIDTH, VGA_HEIGHT);
        }
        return false;
    }

    size_t framebuffer_cols = framebuffer_text_cols_for_size(info->width, info->height);
    if (had_framebuffer) {
        resize_text_geometry(framebuffer_cols, FRAMEBUFFER_TEXT_ROWS);
    } else {
        set_text_geometry(framebuffer_cols, FRAMEBUFFER_TEXT_ROWS);
    }

    g_fb_info = *info;
    g_fb_info.text_cols = (uint32_t)text_cols;
    g_fb_info.text_rows = (uint32_t)text_rows;
    g_fb_info.size = info->pitch * info->height;

    uint32_t used_mask = 0u;
    if (g_fb_info.red_length != 0u) {
        used_mask |= ((1u << g_fb_info.red_length) - 1u) << g_fb_info.red_offset;
    }
    if (g_fb_info.green_length != 0u) {
        used_mask |= ((1u << g_fb_info.green_length) - 1u) << g_fb_info.green_offset;
    }
    if (g_fb_info.blue_length != 0u) {
        used_mask |= ((1u << g_fb_info.blue_length) - 1u) << g_fb_info.blue_offset;
    }
    if (info->bpp <= 32u && g_fb_info.transp_length == 0u) {
        for (uint8_t bit = 0; bit < info->bpp; ++bit) {
            if ((used_mask & (1u << bit)) == 0u) {
                if (g_fb_info.transp_length == 0u) {
                    g_fb_info.transp_offset = bit;
                }
                ++g_fb_info.transp_length;
            }
        }
    }

    g_fb_base = (volatile uint8_t*)(uintptr_t)info->phys_addr;
    g_fb_flush_callback = flush_callback;
    update_framebuffer_text_metrics();
    for (size_t i = 0; i < 16; ++i) {
        g_fb_palette[i] = pack_fb_color(g_vga_palette_rgb[i][0], g_vga_palette_rgb[i][1], g_vga_palette_rgb[i][2]);
    }
    return true;
}

static void setup_framebuffer(const struct mb2_framebuffer_info* fb) {
    struct console_framebuffer_info info;
    memset(&info, 0, sizeof(info));
    if (fb == NULL) {
        (void)setup_framebuffer_info(NULL, NULL);
        return;
    }
    info.present = true;
    info.phys_addr = fb->addr;
    info.pitch = fb->pitch;
    info.width = fb->width;
    info.height = fb->height;
    info.bpp = fb->bpp;
    info.red_offset = fb->red_field_position;
    info.red_length = fb->red_mask_size;
    info.green_offset = fb->green_field_position;
    info.green_length = fb->green_mask_size;
    info.blue_offset = fb->blue_field_position;
    info.blue_length = fb->blue_mask_size;
    (void)setup_framebuffer_info(&info, NULL);
}

static void enter_alt_mode(void) {
    if (alt_mode_active) {
        return;
    }

    for (size_t i = 0; i < cell_count(); ++i) {
        main_vga[i] = text_cells[i];
        main_vga_flags[i] = text_cell_flags[i];
    }

    saved_cursor_row = cursor_row;
    saved_cursor_col = cursor_col;
    saved_color = color;
    saved_base_fg = base_fg;
    saved_base_bg = base_bg;
    saved_sgr_bold = sgr_bold;
    saved_sgr_reverse = sgr_reverse;
    saved_sgr_underline = sgr_underline;
    saved_sgr_blink = sgr_blink;
    saved_sgr_invisible = sgr_invisible;
    saved_g1_charset_graphics = g1_charset_graphics;
    saved_shift_out_active = shift_out_active;
    alt_mode_active = true;
    cursor_row = 0;
    cursor_col = 0;
    scroll_top = 0;
    scroll_bottom = text_rows - 1u;
    clear_screen_entire();
    update_hw_cursor();
}

static void exit_alt_mode(void) {
    if (!alt_mode_active) {
        return;
    }

    for (size_t i = 0; i < cell_count(); ++i) {
        text_cells[i] = main_vga[i];
        text_cell_flags[i] = main_vga_flags[i];
    }

    cursor_row = saved_cursor_row;
    cursor_col = saved_cursor_col;
    color = saved_color;
    base_fg = saved_base_fg;
    base_bg = saved_base_bg;
    sgr_bold = saved_sgr_bold;
    sgr_reverse = saved_sgr_reverse;
    sgr_underline = saved_sgr_underline;
    sgr_blink = saved_sgr_blink;
    sgr_invisible = saved_sgr_invisible;
    g1_charset_graphics = saved_g1_charset_graphics;
    shift_out_active = saved_shift_out_active;
    scroll_top = 0;
    scroll_bottom = text_rows - 1u;
    alt_mode_active = false;
    present_all();
    update_hw_cursor();
}

static bool handle_ansi_char(char c) {
    if (ansi_state == 0) {
        if ((unsigned char)c == 0x1B) {
            ansi_state = 1;
            ansi_len = 0;
            return true;
        }
        return false;
    }

    if (ansi_state == 1) {
        if (c == '[') {
            ansi_state = 2;
            ansi_len = 0;
            return true;
        }
        if (c == ')') {
            ansi_state = 3;
            ansi_len = 0;
            return true;
        }
        if (c == '(' || c == '*' || c == '+') {
            ansi_state = 5;
            ansi_len = 0;
            return true;
        }
        if (c == ']') {
            ansi_state = 4;
            ansi_len = 0;
            return true;
        }
        if (c == '7') {
            saved_cursor_row = cursor_row;
            saved_cursor_col = cursor_col;
            ansi_state = 0;
            return true;
        }
        if (c == '8') {
            cursor_row = saved_cursor_row;
            cursor_col = saved_cursor_col;
            update_hw_cursor();
            ansi_state = 0;
            return true;
        }
        if (c == 'D') {
            linefeed();
            update_hw_cursor();
            ansi_state = 0;
            return true;
        }
        if (c == 'E') {
            cursor_col = 0;
            linefeed();
            update_hw_cursor();
            ansi_state = 0;
            return true;
        }
        if (c == 'M') {
            reverse_index();
            update_hw_cursor();
            ansi_state = 0;
            return true;
        }
        if (c == 'H') {
            set_tab_stop();
            ansi_state = 0;
            return true;
        }
        if (c == 'c') {
            reset_console_state();
            cursor_row = 0;
            cursor_col = 0;
            clear_screen_entire();
            update_hw_cursor();
            ansi_state = 0;
            return true;
        }
        ansi_state = 0;
        return true;
    }

    if (ansi_state == 2) {
        if (ansi_len + 1 < sizeof(ansi_buf)) {
            ansi_buf[ansi_len++] = c;
        }

        if ((unsigned char)c >= 0x40u && (unsigned char)c <= 0x7Eu) {
            unsigned params[4] = {0, 0, 0, 0};
            bool private_mode = false;
            size_t param_count = parse_ansi_params(params, 4, &private_mode);

            if (c == 'K') {
                unsigned mode = ansi_param_or_default(params, param_count, 0, 0u);
                if (mode == 2u) {
                    clear_entire_line();
                } else if (mode == 1u) {
                    clear_line_to_cursor();
                } else {
                    clear_line_from_cursor();
                }
            } else if (c == 'J') {
                unsigned mode = ansi_param_or_default(params, param_count, 0, 0u);
                if (mode == 2u) {
                    clear_screen_entire();
                } else if (mode == 1u) {
                    clear_screen_to_cursor();
                } else {
                    clear_screen_from_cursor();
                }
            } else if (c == 'H' || c == 'f') {
                unsigned row = ansi_param_or_default(params, param_count, 0, 1u);
                unsigned col = ansi_param_or_default(params, param_count, 1, 1u);
                move_cursor_to(row, col);
            } else if (c == 'A') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative(-(int)n, 0);
            } else if (c == 'B') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative((int)n, 0);
            } else if (c == 'C') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative(0, (int)n);
            } else if (c == 'D') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative(0, -(int)n);
            } else if (c == 'G') {
                unsigned col = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_to((unsigned)(cursor_row + 1u), col);
            } else if (c == 'd') {
                unsigned row = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_to(row, (unsigned)(cursor_col + 1u));
            } else if (c == 'I') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                cursor_tab_forward(n);
            } else if (c == 'Z') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                cursor_tab_backward(n);
            } else if (c == 'L') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                insert_lines(n);
            } else if (c == 'M') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                delete_lines(n);
            } else if (c == '@') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                insert_blank_chars(n);
            } else if (c == 'P') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                delete_chars(n);
            } else if (c == 'X') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                erase_chars(n);
            } else if (c == 'S') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                scroll_up_region(scroll_top, scroll_bottom, n);
            } else if (c == 'T') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                scroll_down_region(scroll_top, scroll_bottom, n);
            } else if (c == 'b') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                repeat_last_printed_char(n);
            } else if (c == 'g') {
                unsigned mode = ansi_param_or_default(params, param_count, 0, 0u);
                if (mode == 3u) {
                    clear_all_tab_stops();
                } else {
                    clear_tab_stop_at_cursor();
                }
            } else if (c == 'r') {
                unsigned top = ansi_param_or_default(params, param_count, 0, 1u);
                unsigned bottom = ansi_param_or_default(params, param_count, 1, (unsigned)text_rows);
                set_scroll_region(top, bottom);
            } else if (c == 'm') {
                if (param_count == 0) {
                    reset_text_attributes();
                }
                for (size_t i = 0; i < param_count; ++i) {
                    unsigned value = params[i];
                    if (value == 0u) {
                        reset_text_attributes();
                    } else if (value == 1u) {
                        sgr_bold = true;
                    } else if (value == 4u) {
                        sgr_underline = true;
                    } else if (value == 5u) {
                        sgr_blink = true;
                    } else if (value == 7u) {
                        sgr_reverse = true;
                    } else if (value == 8u) {
                        sgr_invisible = true;
                    } else if (value == 10u) {
                        shift_out_active = false;
                        g1_charset_graphics = false;
                    } else if (value == 11u) {
                        shift_out_active = true;
                        g1_charset_graphics = true;
                    } else if (value == 22u) {
                        sgr_bold = false;
                    } else if (value == 24u) {
                        sgr_underline = false;
                    } else if (value == 25u) {
                        sgr_blink = false;
                    } else if (value == 27u) {
                        sgr_reverse = false;
                    } else if (value == 28u) {
                        sgr_invisible = false;
                    } else if (value >= 30u && value <= 37u) {
                        base_fg = (uint8_t)(value - 30u);
                    } else if (value == 39u) {
                        base_fg = 0x07u;
                    } else if (value >= 40u && value <= 47u) {
                        base_bg = (uint8_t)(value - 40u);
                    } else if (value == 49u) {
                        base_bg = 0x00u;
                    } else if (value >= 90u && value <= 97u) {
                        base_fg = (uint8_t)(value - 90u);
                        sgr_bold = true;
                    } else if (value >= 100u && value <= 107u) {
                        base_bg = (uint8_t)(value - 100u);
                    }
                }
                apply_text_attributes();
            } else if (c == 's') {
                saved_cursor_row = cursor_row;
                saved_cursor_col = cursor_col;
            } else if (c == 'u') {
                cursor_row = saved_cursor_row;
                cursor_col = saved_cursor_col;
            } else if (c == 'h' && private_mode) {
                for (size_t i = 0; i < param_count; ++i) {
                    if (params[i] == 1u) {
                        keyboard_set_application_cursor_keys(true);
                    } else if (params[i] == 25u) {
                        cursor_visible = true;
                    } else if (params[i] == 1049u) {
                        enter_alt_mode();
                    }
                }
            } else if (c == 'l' && private_mode) {
                for (size_t i = 0; i < param_count; ++i) {
                    if (params[i] == 1u) {
                        keyboard_set_application_cursor_keys(false);
                    } else if (params[i] == 25u) {
                        cursor_visible = false;
                    } else if (params[i] == 1049u) {
                        exit_alt_mode();
                    }
                }
            } else if (c == 'n' && param_count > 0 && params[0] == 6u) {
                enqueue_cursor_position_report();
            } else if (c == 'c') {
                input_enqueue_response_string("\x1b[?1;0c");
            } else if (c == 'i') {
                // ANSI printer controller modes are accepted but have no printer backend.
            }
            ansi_state = 0;
            update_hw_cursor();
        }
        return true;
    }

    if (ansi_state == 3) {
        g1_charset_graphics = (c == '0');
        ansi_state = 0;
        return true;
    }

    if (ansi_state == 4) {
        if (ansi_len + 1 < sizeof(ansi_buf)) {
            ansi_buf[ansi_len++] = c;
        }

        if (c == '\a' || c == 'R' || (ansi_len == 8u && ansi_buf[0] == 'P')) {
            ansi_state = 0;
        }
        return true;
    }

    if (ansi_state == 5) {
        ansi_state = 0;
        return true;
    }

    ansi_state = 0;
    return false;
}

void console_init(uint64_t mb2_info) {
    struct mb2_framebuffer_info fb;

    serial_init();
    memset(&fb, 0, sizeof(fb));
    if (mb2_find_framebuffer(mb2_info, &fb)) {
        setup_framebuffer(&fb);
    } else {
        memset(&g_fb_info, 0, sizeof(g_fb_info));
        g_fb_base = NULL;
        g_fb_flush_callback = NULL;
        set_text_geometry(VGA_WIDTH, VGA_HEIGHT);
    }
    reset_console_state();
    console_clear();
}

bool console_configure_framebuffer(const struct console_framebuffer_info* info, console_framebuffer_flush_fn flush_callback) {
    soft_cursor_drawn = false;
    g_fb_bulk_depth = 0;
    g_fb_bulk_dirty = false;
    if (!setup_framebuffer_info(info, flush_callback)) {
        return false;
    }
    clamp_cursor();
    reset_tab_stops();
    present_all();
    update_hw_cursor();
    return true;
}

void console_set_color(unsigned fg, unsigned bg) {
    base_fg = (uint8_t)(fg & 0x07u);
    base_bg = (uint8_t)(bg & 0x07u);
    sgr_bold = (fg & 0x08u) != 0u;
    sgr_reverse = false;
    apply_text_attributes();
}

void console_clear(void) {
    cursor_row = 0;
    cursor_col = 0;
    scroll_top = 0;
    scroll_bottom = text_rows - 1u;
    clear_screen_entire();
    update_hw_cursor();
}

bool console_get_framebuffer_info(struct console_framebuffer_info* out) {
    if (out == NULL) {
        return false;
    }
    *out = g_fb_info;
    return out->present;
}

void console_flush_framebuffer(void) {
    if (!framebuffer_active()) {
        return;
    }
    framebuffer_flush_rect(0, 0, g_fb_info.width, g_fb_info.height);
}

void console_putc(char c) {
    if (c == '\a') {
        return;
    }

    if (c == '\016') {
        serial_putc(c);
        shift_out_active = true;
        return;
    }

    if (c == '\017') {
        serial_putc(c);
        shift_out_active = false;
        return;
    }

    if (handle_ansi_char(c)) {
        serial_putc(c);
        return;
    }

    clamp_cursor();

    if (c == '\t') {
        serial_putc(c);
        cursor_tab_forward(1);
        update_hw_cursor();
        return;
    }

    if (c == '\n') {
        cursor_col = 0;
        serial_putc('\r');
        serial_putc('\n');
        linefeed();
        update_hw_cursor();
        return;
    }

    if (c == '\r') {
        cursor_col = 0;
        serial_putc('\r');
        update_hw_cursor();
        return;
    }

    if (c == '\b') {
        if (cursor_col > 0) {
            --cursor_col;
            // Terminal backspace moves left; destructive erase is emitted as "\b \b".
            serial_putc('\b');
        }
        update_hw_cursor();
        return;
    }

    serial_putc(c);
    last_printed_char = (uint8_t)c;
    text_cells[cell_index(cursor_row, cursor_col)] = ((uint16_t)color << 8) | translate_graphics_char((uint8_t)c);
    text_cell_flags[cell_index(cursor_row, cursor_col)] = current_cell_flags();
    present_row_range(cursor_row, cursor_col, cursor_col + 1u);
    ++cursor_col;
    if (cursor_col >= text_cols) {
        cursor_col = 0;
        linefeed();
    }
    update_hw_cursor();
}

void console_write(const char* s) {
    framebuffer_begin_bulk();
    while (*s != '\0') {
        console_putc(*s++);
    }
    framebuffer_end_bulk();
}

void console_writen(const char* s, size_t n) {
    framebuffer_begin_bulk();
    for (size_t i = 0; i < n; ++i) {
        console_putc(s[i]);
    }
    framebuffer_end_bulk();
}

static void print_unsigned(uint64_t value, unsigned base) {
    char buf[32];
    size_t idx = 0;

    if (value == 0) {
        console_putc('0');
        return;
    }

    while (value > 0) {
        unsigned digit = (unsigned)(value % base);
        buf[idx++] = (char)(digit < 10 ? ('0' + digit) : ('a' + (digit - 10)));
        value /= base;
    }

    while (idx > 0) {
        console_putc(buf[--idx]);
    }
}

void console_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    while (*fmt != '\0') {
        if (*fmt != '%') {
            console_putc(*fmt++);
            continue;
        }

        ++fmt;
        switch (*fmt) {
            case '%':
                console_putc('%');
                break;
            case 'c':
                console_putc((char)va_arg(ap, int));
                break;
            case 's': {
                const char* s = va_arg(ap, const char*);
                if (s == NULL) {
                    s = "(null)";
                }
                console_write(s);
                break;
            }
            case 'd': {
                int v = va_arg(ap, int);
                if (v < 0) {
                    console_putc('-');
                    print_unsigned((uint64_t)(-v), 10);
                } else {
                    print_unsigned((uint64_t)v, 10);
                }
                break;
            }
            case 'u':
                print_unsigned((uint64_t)va_arg(ap, unsigned), 10);
                break;
            case 'x':
            case 'p':
                print_unsigned((uint64_t)va_arg(ap, uint64_t), 16);
                break;
            default:
                console_putc('?');
                break;
        }
        ++fmt;
    }

    va_end(ap);
}
