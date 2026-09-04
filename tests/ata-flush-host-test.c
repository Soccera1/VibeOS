#include "io.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(e)                                                                                                       \
    do {                                                                                                               \
        if (!(e)) {                                                                                                    \
            fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #e);                                            \
            exit(1);                                                                                                   \
        }                                                                                                              \
    } while (0)
static unsigned selects, flushes, polls, busy_polls;
static uint8_t before_status = 0x40, after_status = 0x40, expected_select;
static bool issued;
static uint8_t test_inb(uint16_t port) {
    CHECK(port == 0x177 || port == 0x376);
    if (port == 0x376)
        return 0x40;
    if (issued) {
        ++polls;
        if (polls <= busy_polls)
            return 0x80;
        return after_status;
    }
    return before_status;
}
static void test_outb(uint16_t port, uint8_t value) {
    if (port == 0x176) {
        CHECK(value == expected_select);
        ++selects;
    } else {
        CHECK(port == 0x177 && value == 0xe7 && selects == 1);
        ++flushes;
        issued = true;
    }
}
#define inb test_inb
#define outb test_outb
#include "../kernel/src/ata.c"
#undef inb
#undef outb

static void reset(void) {
    selects = flushes = polls = busy_polls = 0;
    before_status = after_status = 0x40;
    expected_select = 0xf0;
    issued = false;
}
int main(void) {
    struct ata_device dev = {.present = true, .io_base = 0x170, .ctrl_base = 0x376, .slave = true};
    const struct ext2_storage_ops* ops = ata_secondary_storage_ops();
    CHECK(ops->flush);
    reset();
    busy_polls = 3;
    CHECK(ops->flush(&dev) == 0 && selects == 1 && flushes == 1 && polls > busy_polls);
    reset();
    dev.slave = false;
    expected_select = 0xe0;
    CHECK(ops->flush(&dev) == 0 && flushes == 1);
    dev.slave = true;
    const uint8_t failures[] = {0, 0xff, 0x41, 0x60, 0x48, 0x80};
    for (size_t i = 0; i < sizeof(failures); ++i) {
        reset();
        after_status = failures[i];
        CHECK(ops->flush(&dev) == -1 && flushes == 1);
        reset();
        before_status = failures[i];
        CHECK(ops->flush(&dev) == -1 && flushes == 0);
    }
    reset();
    dev.present = false;
    CHECK(ops->flush(&dev) == -1 && selects == 0 && flushes == 0);
    CHECK(ops->flush(NULL) == -1 && selects == 0 && flushes == 0);
    puts("ATA flush checks passed");
    return 0;
}
