#pragma once

#include <stdint.h>

void power_init(uint64_t mb2_info);
void power_shutdown(void) __attribute__((noreturn));
void power_halt(void) __attribute__((noreturn));
void power_reboot(void) __attribute__((noreturn));
