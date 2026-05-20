#pragma once

#include <stdbool.h>

void virtio_gpu_init(void);
void virtio_gpu_poll(void);
bool virtio_gpu_present(void);
