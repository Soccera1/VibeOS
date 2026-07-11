#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Include the console so the test can exercise its internal reflow state directly. */
#include "../kernel/src/console.c"

#define CHECK(condition)                                                                                               \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            fprintf(stderr, "console reflow check failed at line %d: %s\n", __LINE__, #condition);                    \
            return false;                                                                                              \
        }                                                                                                              \
    } while (0)

static void init_screen(size_t cols, size_t rows) {
    text_cols = cols;
    text_rows = rows;
    cursor_row = 0u;
    cursor_col = 0u;
    saved_cursor_row = 0u;
    saved_cursor_col = 0u;
    alt_mode_active = false;

    uint16_t blank = blank_cell();
    for (size_t i = 0; i < TEXT_CELL_CAPACITY; ++i) {
        text_cells[i] = blank;
        text_cell_flags[i] = 0u;
    }
    for (size_t row = 0; row < FB_MAX_ROWS; ++row) {
        text_line_lengths[row] = 0u;
        text_line_wrapped[row] = false;
    }
}

static void put_row(size_t row, const char* value, bool wrapped) {
    size_t col = 0u;
    while (value[col] != '\0') {
        text_cells[row * text_cols + col] = (uint16_t)(0x0700u | (uint8_t)value[col]);
        ++col;
    }
    text_line_lengths[row] = col;
    text_line_wrapped[row] = wrapped;
}

static bool row_starts_with(size_t row, const char* expected) {
    for (size_t col = 0u; expected[col] != '\0'; ++col) {
        CHECK((uint8_t)text_cells[row * text_cols + col] == (uint8_t)expected[col]);
    }
    return true;
}

static bool test_soft_wrapped_line_survives_round_trip(void) {
    init_screen(10u, 5u);
    put_row(0u, "abcdefghij", true);
    put_row(1u, "klm", false);
    cursor_row = 1u;
    cursor_col = 3u;

    resize_text_geometry(5u, 5u);
    CHECK(row_starts_with(0u, "abcde"));
    CHECK(row_starts_with(1u, "fghij"));
    CHECK(row_starts_with(2u, "klm"));
    CHECK(text_line_wrapped[0u]);
    CHECK(text_line_wrapped[1u]);
    CHECK(!text_line_wrapped[2u]);
    CHECK(cursor_row == 2u && cursor_col == 3u);

    resize_text_geometry(10u, 5u);
    CHECK(row_starts_with(0u, "abcdefghij"));
    CHECK(row_starts_with(1u, "klm"));
    CHECK(text_line_wrapped[0u]);
    CHECK(!text_line_wrapped[1u]);
    CHECK(cursor_row == 1u && cursor_col == 3u);
    return true;
}

static bool test_hard_newlines_remain_separate(void) {
    init_screen(10u, 5u);
    put_row(0u, "abc", false);
    put_row(1u, "def", false);
    cursor_row = 1u;
    cursor_col = 3u;

    resize_text_geometry(2u, 5u);
    CHECK(row_starts_with(0u, "ab"));
    CHECK(row_starts_with(1u, "c"));
    CHECK(row_starts_with(2u, "de"));
    CHECK(row_starts_with(3u, "f"));
    CHECK(text_line_wrapped[0u]);
    CHECK(!text_line_wrapped[1u]);
    CHECK(text_line_wrapped[2u]);
    CHECK(!text_line_wrapped[3u]);
    return true;
}

static bool decode_sequence(const uint8_t* bytes, size_t length, uint8_t expected_glyph) {
    uint32_t codepoint = 0u;
    utf8_bytes_remaining = 0u;
    for (size_t i = 0u; i < length; ++i) {
        enum utf8_decode_result result = decode_utf8_byte(bytes[i], &codepoint);
        if (i + 1u < length) {
            CHECK(result == UTF8_DECODE_INCOMPLETE);
        } else {
            CHECK(result == UTF8_DECODE_COMPLETE);
        }
    }
    CHECK(unicode_to_console_glyph(codepoint) == expected_glyph);
    return true;
}

static bool test_utf8_is_decoded_before_glyph_lookup(void) {
    static const uint8_t hyphen[] = {0xe2u, 0x80u, 0x90u};
    static const uint8_t right_quote[] = {0xe2u, 0x80u, 0x99u};
    static const uint8_t plus_minus[] = {0xc2u, 0xb1u};

    CHECK(decode_sequence(hyphen, sizeof(hyphen), '-'));
    CHECK(decode_sequence(right_quote, sizeof(right_quote), '\''));
    CHECK(decode_sequence(plus_minus, sizeof(plus_minus), 241u));
    return true;
}

int main(void) {
    if (!test_soft_wrapped_line_survives_round_trip() || !test_hard_newlines_remain_separate() ||
        !test_utf8_is_decoded_before_glyph_lookup()) {
        return 1;
    }
    puts("console reflow host tests passed");
    return 0;
}
