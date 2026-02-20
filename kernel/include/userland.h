#pragma once

#include <stdint.h>

int userland_run_busybox(void);
void userland_get_image_span(uint64_t* start_out, uint64_t* end_out);
void userland_set_image_span(uint64_t start, uint64_t end);
__attribute__((noreturn)) void userland_exit_handler(uint64_t code);
extern uint64_t kernel_exit_stack_top;
