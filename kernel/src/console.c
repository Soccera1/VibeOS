#include "console.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "console_font.h"
#include "io.h"
#include "multiboot2.h"
#include "serial.h"
#include "string.h"

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define TAB_WIDTH 8
#define FONT_WIDTH 8
#define FONT_HEIGHT 16
#define TEXT_PIXEL_WIDTH (VGA_WIDTH * FONT_WIDTH)
#define TEXT_PIXEL_HEIGHT (VGA_HEIGHT * FONT_HEIGHT)
#define VGA_CRTC_INDEX 0x3D4
#define VGA_CRTC_DATA 0x3D5

static volatile uint16_t* const vga_hw = (volatile uint16_t*)0xB8000;
static uint16_t text_cells[VGA_WIDTH * VGA_HEIGHT];
static uint16_t main_vga[VGA_WIDTH * VGA_HEIGHT];
static size_t cursor_row;
static size_t cursor_col;
static uint8_t color = 0x07;
static uint8_t base_fg = 0x07;
static uint8_t base_bg;
static bool sgr_bold;
static bool sgr_reverse;
static uint8_t saved_color;
static size_t saved_cursor_row;
static size_t saved_cursor_col;
static uint8_t saved_base_fg;
static uint8_t saved_base_bg;
static bool saved_sgr_bold;
static bool saved_sgr_reverse;
static bool alt_mode_active;
static size_t scroll_top;
static size_t scroll_bottom = VGA_HEIGHT - 1;
static bool g1_charset_graphics;
static bool shift_out_active;
static bool saved_g1_charset_graphics;
static bool saved_shift_out_active;
static uint8_t ansi_state;  // 0=none, 1=ESC, 2=CSI, 3=ESC ), 4=OSC
static char ansi_buf[32];
static size_t ansi_len;
static struct console_framebuffer_info g_fb_info;
static volatile uint8_t* g_fb_base;
static size_t g_fb_origin_x;
static size_t g_fb_origin_y;
static uint32_t g_fb_palette[16];

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
    return row * VGA_WIDTH + col;
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

static void draw_cell(size_t row, size_t col, uint16_t cell) {
    if (!framebuffer_active()) {
        vga_hw[cell_index(row, col)] = cell;
        return;
    }

    uint8_t ch = (uint8_t)(cell & 0xffu);
    uint8_t attr = (uint8_t)(cell >> 8);
    uint32_t fg = g_fb_palette[attr & 0x0fu];
    uint32_t bg = g_fb_palette[(attr >> 4) & 0x0fu];
    size_t x0 = g_fb_origin_x + col * FONT_WIDTH;
    size_t y0 = g_fb_origin_y + row * FONT_HEIGHT;

    for (size_t glyph_row = 0; glyph_row < FONT_HEIGHT; ++glyph_row) {
        uint8_t bits = g_console_font[ch][glyph_row];
        for (size_t glyph_col = 0; glyph_col < FONT_WIDTH; ++glyph_col) {
            uint32_t pixel = ((bits & (0x80u >> glyph_col)) != 0u) ? fg : bg;
            fb_store_pixel(x0 + glyph_col, y0 + glyph_row, pixel);
        }
    }
}

static void present_row_range(size_t row, size_t start_col, size_t end_col) {
    if (row >= VGA_HEIGHT || start_col >= VGA_WIDTH) {
        return;
    }
    if (end_col > VGA_WIDTH) {
        end_col = VGA_WIDTH;
    }

    for (size_t x = start_col; x < end_col; ++x) {
        draw_cell(row, x, text_cells[cell_index(row, x)]);
    }
}

static void present_rows(size_t start_row, size_t end_row) {
    if (end_row > VGA_HEIGHT) {
        end_row = VGA_HEIGHT;
    }
    for (size_t row = start_row; row < end_row; ++row) {
        present_row_range(row, 0, VGA_WIDTH);
    }
}

static void present_all(void) {
    if (framebuffer_active()) {
        fb_fill_rect(0, 0, g_fb_info.width, g_fb_info.height, g_fb_palette[0]);
    }
    present_rows(0, VGA_HEIGHT);
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

    color = (uint8_t)((bg << 4) | (fg & 0x0Fu));
}

static void reset_text_attributes(void) {
    base_fg = 0x07u;
    base_bg = 0x00u;
    sgr_bold = false;
    sgr_reverse = false;
    apply_text_attributes();
}

static void clear_row_range(size_t row, size_t start_col, size_t end_col) {
    if (row >= VGA_HEIGHT || start_col >= VGA_WIDTH) {
        return;
    }

    if (end_col > VGA_WIDTH) {
        end_col = VGA_WIDTH;
    }

    for (size_t x = start_col; x < end_col; ++x) {
        text_cells[cell_index(row, x)] = blank_cell();
    }
    present_row_range(row, start_col, end_col);
}

static void clear_screen_entire(void) {
    uint16_t blank = blank_cell();
    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        text_cells[i] = blank;
    }
    present_all();
}

static void scroll_up_region(size_t top, size_t bottom, size_t lines) {
    if (top >= VGA_HEIGHT || bottom >= VGA_HEIGHT || top > bottom) {
        return;
    }

    size_t height = bottom - top + 1u;
    if (lines >= height) {
        for (size_t y = top; y <= bottom; ++y) {
            clear_row_range(y, 0, VGA_WIDTH);
        }
        return;
    }

    memmove(&text_cells[cell_index(top, 0)], &text_cells[cell_index(top + lines, 0)],
            (height - lines) * VGA_WIDTH * sizeof(text_cells[0]));
    for (size_t y = bottom + 1u - lines; y <= bottom; ++y) {
        for (size_t x = 0; x < VGA_WIDTH; ++x) {
            text_cells[cell_index(y, x)] = blank_cell();
        }
    }
    present_rows(top, bottom + 1u);
}

static void scroll_down_region(size_t top, size_t bottom, size_t lines) {
    if (top >= VGA_HEIGHT || bottom >= VGA_HEIGHT || top > bottom) {
        return;
    }

    size_t height = bottom - top + 1u;
    if (lines >= height) {
        for (size_t y = top; y <= bottom; ++y) {
            clear_row_range(y, 0, VGA_WIDTH);
        }
        return;
    }

    memmove(&text_cells[cell_index(top + lines, 0)], &text_cells[cell_index(top, 0)],
            (height - lines) * VGA_WIDTH * sizeof(text_cells[0]));
    for (size_t y = top; y < top + lines; ++y) {
        for (size_t x = 0; x < VGA_WIDTH; ++x) {
            text_cells[cell_index(y, x)] = blank_cell();
        }
    }
    present_rows(top, bottom + 1u);
}

static void clamp_cursor(void) {
    if (cursor_row >= VGA_HEIGHT) {
        cursor_row = VGA_HEIGHT - 1;
    }
    if (cursor_col >= VGA_WIDTH) {
        cursor_col = VGA_WIDTH - 1;
    }
}

static void update_hw_cursor(void) {
    clamp_cursor();
    if (framebuffer_active()) {
        return;
    }
    size_t row = cursor_row;
    size_t col = cursor_col;
    uint16_t pos = (uint16_t)(row * VGA_WIDTH + col);
    outb(VGA_CRTC_INDEX, 0x0F);
    outb(VGA_CRTC_DATA, (uint8_t)(pos & 0xFFu));
    outb(VGA_CRTC_INDEX, 0x0E);
    outb(VGA_CRTC_DATA, (uint8_t)((pos >> 8) & 0xFFu));
}

static void clear_line_from_cursor(void) {
    clamp_cursor();
    clear_row_range(cursor_row, cursor_col, VGA_WIDTH);
}

static void clear_screen_from_cursor(void) {
    clamp_cursor();
    clear_line_from_cursor();

    for (size_t y = cursor_row + 1; y < VGA_HEIGHT; ++y) {
        clear_row_range(y, 0, VGA_WIDTH);
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
    } else if (row >= (int)VGA_HEIGHT) {
        row = (int)VGA_HEIGHT - 1;
    }

    if (col < 0) {
        col = 0;
    } else if (col >= (int)VGA_WIDTH) {
        col = (int)VGA_WIDTH - 1;
    }

    cursor_row = (size_t)row;
    cursor_col = (size_t)col;
}

static void clear_entire_line(void) {
    clamp_cursor();
    clear_row_range(cursor_row, 0, VGA_WIDTH);
}

static void clear_line_to_cursor(void) {
    clamp_cursor();
    clear_row_range(cursor_row, 0, cursor_col + 1u);
}

static void clear_screen_to_cursor(void) {
    clamp_cursor();

    for (size_t y = 0; y < cursor_row; ++y) {
        clear_row_range(y, 0, VGA_WIDTH);
    }

    clear_row_range(cursor_row, 0, cursor_col + 1u);
}

static void insert_blank_chars(size_t count) {
    clamp_cursor();
    if (count == 0 || cursor_col >= VGA_WIDTH) {
        return;
    }
    if (count > VGA_WIDTH - cursor_col) {
        count = VGA_WIDTH - cursor_col;
    }

    size_t row_base = cursor_row * VGA_WIDTH;
    memmove(&text_cells[row_base + cursor_col + count], &text_cells[row_base + cursor_col],
            (VGA_WIDTH - cursor_col - count) * sizeof(text_cells[0]));
    for (size_t x = cursor_col; x < cursor_col + count; ++x) {
        text_cells[row_base + x] = blank_cell();
    }
    present_row_range(cursor_row, cursor_col, VGA_WIDTH);
}

static void delete_chars(size_t count) {
    clamp_cursor();
    if (count == 0 || cursor_col >= VGA_WIDTH) {
        return;
    }
    if (count > VGA_WIDTH - cursor_col) {
        count = VGA_WIDTH - cursor_col;
    }

    size_t row_base = cursor_row * VGA_WIDTH;
    memmove(&text_cells[row_base + cursor_col], &text_cells[row_base + cursor_col + count],
            (VGA_WIDTH - cursor_col - count) * sizeof(text_cells[0]));
    for (size_t x = VGA_WIDTH - count; x < VGA_WIDTH; ++x) {
        text_cells[row_base + x] = blank_cell();
    }
    present_row_range(cursor_row, cursor_col, VGA_WIDTH);
}

static void erase_chars(size_t count) {
    clamp_cursor();
    if (count == 0) {
        return;
    }
    if (count > VGA_WIDTH - cursor_col) {
        count = VGA_WIDTH - cursor_col;
    }
    clear_row_range(cursor_row, cursor_col, cursor_col + count);
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
    } else if (cursor_row == VGA_HEIGHT - 1u) {
        scroll_up_region(0, VGA_HEIGHT - 1u, 1u);
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
        scroll_down_region(0, VGA_HEIGHT - 1u, 1u);
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
        bottom_1based = VGA_HEIGHT;
    }
    if (top_1based > VGA_HEIGHT || bottom_1based > VGA_HEIGHT || top_1based >= bottom_1based) {
        scroll_top = 0;
        scroll_bottom = VGA_HEIGHT - 1u;
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
    scroll_bottom = VGA_HEIGHT - 1u;
    g1_charset_graphics = false;
    shift_out_active = false;
    reset_text_attributes();
}

static void setup_framebuffer(const struct mb2_framebuffer_info* fb) {
    memset(&g_fb_info, 0, sizeof(g_fb_info));
    g_fb_base = NULL;
    g_fb_origin_x = 0;
    g_fb_origin_y = 0;

    if (fb == NULL || fb->addr == 0 || fb->addr >= (1ull << 32) || fb->width < TEXT_PIXEL_WIDTH || fb->height < TEXT_PIXEL_HEIGHT) {
        return;
    }
    if (fb->bpp != 15u && fb->bpp != 16u && fb->bpp != 24u && fb->bpp != 32u) {
        return;
    }

    g_fb_info.present = true;
    g_fb_info.phys_addr = fb->addr;
    g_fb_info.pitch = fb->pitch;
    g_fb_info.width = fb->width;
    g_fb_info.height = fb->height;
    g_fb_info.bpp = fb->bpp;
    g_fb_info.size = fb->pitch * fb->height;
    g_fb_info.red_offset = fb->red_field_position;
    g_fb_info.red_length = fb->red_mask_size;
    g_fb_info.green_offset = fb->green_field_position;
    g_fb_info.green_length = fb->green_mask_size;
    g_fb_info.blue_offset = fb->blue_field_position;
    g_fb_info.blue_length = fb->blue_mask_size;

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
    if (fb->bpp <= 32u) {
        for (uint8_t bit = 0; bit < fb->bpp; ++bit) {
            if ((used_mask & (1u << bit)) == 0u) {
                if (g_fb_info.transp_length == 0u) {
                    g_fb_info.transp_offset = bit;
                }
                ++g_fb_info.transp_length;
            }
        }
    }

    g_fb_base = (volatile uint8_t*)(uintptr_t)fb->addr;
    g_fb_origin_x = (fb->width - TEXT_PIXEL_WIDTH) / 2u;
    g_fb_origin_y = (fb->height - TEXT_PIXEL_HEIGHT) / 2u;
    for (size_t i = 0; i < 16; ++i) {
        g_fb_palette[i] = pack_fb_color(g_vga_palette_rgb[i][0], g_vga_palette_rgb[i][1], g_vga_palette_rgb[i][2]);
    }
}

static void enter_alt_mode(void) {
    if (alt_mode_active) {
        return;
    }

    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        main_vga[i] = text_cells[i];
    }

    saved_cursor_row = cursor_row;
    saved_cursor_col = cursor_col;
    saved_color = color;
    saved_base_fg = base_fg;
    saved_base_bg = base_bg;
    saved_sgr_bold = sgr_bold;
    saved_sgr_reverse = sgr_reverse;
    saved_g1_charset_graphics = g1_charset_graphics;
    saved_shift_out_active = shift_out_active;
    alt_mode_active = true;
    cursor_row = 0;
    cursor_col = 0;
    scroll_top = 0;
    scroll_bottom = VGA_HEIGHT - 1u;
    clear_screen_entire();
    update_hw_cursor();
}

static void exit_alt_mode(void) {
    if (!alt_mode_active) {
        return;
    }

    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        text_cells[i] = main_vga[i];
    }

    cursor_row = saved_cursor_row;
    cursor_col = saved_cursor_col;
    color = saved_color;
    base_fg = saved_base_fg;
    base_bg = saved_base_bg;
    sgr_bold = saved_sgr_bold;
    sgr_reverse = saved_sgr_reverse;
    g1_charset_graphics = saved_g1_charset_graphics;
    shift_out_active = saved_shift_out_active;
    scroll_top = 0;
    scroll_bottom = VGA_HEIGHT - 1u;
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
            } else if (c == 'r') {
                unsigned top = ansi_param_or_default(params, param_count, 0, 1u);
                unsigned bottom = ansi_param_or_default(params, param_count, 1, VGA_HEIGHT);
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
                    } else if (value == 7u) {
                        sgr_reverse = true;
                    } else if (value == 22u) {
                        sgr_bold = false;
                    } else if (value == 27u) {
                        sgr_reverse = false;
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
            } else if (c == 'h' && private_mode && param_count > 0 && params[0] == 25u) {
                /* Cursor visibility is ignored on VGA text mode for now. */
            } else if (c == 'h' && private_mode && param_count > 0 && params[0] == 1049u) {
                enter_alt_mode();
            } else if (c == 'l' && private_mode && param_count > 0 && params[0] == 25u) {
                /* Cursor visibility is ignored on VGA text mode for now. */
            } else if (c == 'l' && private_mode && param_count > 0 && params[0] == 1049u) {
                exit_alt_mode();
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
    }
    reset_console_state();
    console_clear();
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
    scroll_bottom = VGA_HEIGHT - 1u;
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
        size_t spaces = TAB_WIDTH - (cursor_col % TAB_WIDTH);
        if (spaces == 0) {
            spaces = TAB_WIDTH;
        }
        for (size_t i = 0; i < spaces; ++i) {
            console_putc(' ');
        }
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
            text_cells[cell_index(cursor_row, cursor_col)] = ((uint16_t)color << 8) | ' ';
            present_row_range(cursor_row, cursor_col, cursor_col + 1u);
        }
        serial_putc('\b');
        serial_putc(' ');
        serial_putc('\b');
        update_hw_cursor();
        return;
    }

    serial_putc(c);
    text_cells[cell_index(cursor_row, cursor_col)] = ((uint16_t)color << 8) | translate_graphics_char((uint8_t)c);
    present_row_range(cursor_row, cursor_col, cursor_col + 1u);
    ++cursor_col;
    if (cursor_col >= VGA_WIDTH) {
        cursor_col = 0;
        linefeed();
    }
    update_hw_cursor();
}

void console_write(const char* s) {
    while (*s != '\0') {
        console_putc(*s++);
    }
}

void console_writen(const char* s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        console_putc(s[i]);
    }
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
