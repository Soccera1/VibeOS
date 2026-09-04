#include "fpu.h"

#include "io.h"
#include "string.h"

void fpu_save(struct fpu_state* state) {
    memset(state, 0, sizeof(*state));
    if (read_cr4() & (1ull << 18)) {
        __asm__ volatile("xsave64 %0" : "=m"(*state) : "a"(7), "d"(0) : "memory");
    } else {
        __asm__ volatile("fxsave64 %0" : "=m"(*state) : : "memory");
    }
}

void fpu_restore(const struct fpu_state* state) {
    if (read_cr4() & (1ull << 18)) {
        __asm__ volatile("xrstor64 %0" : : "m"(*state), "a"(7), "d"(0) : "memory");
    } else {
        __asm__ volatile("fxrstor64 %0" : : "m"(*state) : "memory");
    }
}

void fpu_reset(void) {
    struct fpu_state initial;
    memset(&initial, 0, sizeof(initial));
    *(uint16_t*)&initial.bytes[0] = 0x037f;
    *(uint32_t*)&initial.bytes[24] = 0x1f80;
    fpu_restore(&initial);
}

bool fpu_state_valid(const struct fpu_state* state) {
    struct fpu_state current;
    fpu_save(&current);
    uint32_t mask = *(const uint32_t*)&current.bytes[28];
    if (mask == 0) mask = 0xffbf;
    if (*(const uint32_t*)&state->bytes[24] & ~mask) return false;
    if (*(const uint64_t*)&state->bytes[512] & ~7ull) return false;
    for (unsigned i = 520; i < 576; ++i) {
        if (state->bytes[i] != 0) return false;
    }
    return true;
}
