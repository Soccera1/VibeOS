#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "ext2.h"

void virtio_scsi_init(void);
bool virtio_scsi_present(void);
size_t virtio_scsi_size(void);
const struct ext2_storage_ops* virtio_scsi_storage_ops(void);
void* virtio_scsi_storage_ctx(void);

