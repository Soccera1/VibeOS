#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "ext2.h"

void virtio_scsi_init(void);
size_t virtio_scsi_disk_count(void);
bool virtio_scsi_disk_present(size_t index);
size_t virtio_scsi_disk_size(size_t index);
const struct ext2_storage_ops* virtio_scsi_disk_storage_ops(size_t index);
void* virtio_scsi_disk_storage_ctx(size_t index);
bool virtio_scsi_present(void);
size_t virtio_scsi_size(void);
const struct ext2_storage_ops* virtio_scsi_storage_ops(void);
void* virtio_scsi_storage_ctx(void);
