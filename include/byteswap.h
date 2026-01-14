#ifndef _BYTESWAP_H
#define _BYTESWAP_H

#include <stdint.h>

static inline uint16_t bswap_16(uint16_t x) {
    return (x << 8) | (x >> 8);
}

static inline uint32_t bswap_32(uint32_t x) {
    return ((x << 24) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | (x >> 24));
}

#endif
