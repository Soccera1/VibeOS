#pragma once

#include <stdint.h>

void timer_init(void);
uint64_t timer_cycles_per_usec(void);
uint64_t timer_monotonic_ns(void);
