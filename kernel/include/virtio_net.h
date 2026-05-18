#pragma once

#include <stdbool.h>
#include <stddef.h>

void virtio_net_init(void);
void virtio_net_poll(void);
bool virtio_net_send(const void* frame, size_t len);
bool virtio_net_present(void);

