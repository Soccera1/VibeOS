#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Standard XSAVE layout for the enabled x87, SSE and AVX components. */
struct fpu_state {
    uint8_t bytes[832];
} __attribute__((aligned(64)));

void fpu_reset(void);
void fpu_save(struct fpu_state* state);
void fpu_restore(const struct fpu_state* state);
bool fpu_state_valid(const struct fpu_state* state);
