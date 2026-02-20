#pragma once

#include <stddef.h>
#include <stdint.h>

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
