#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "ext2.h"

void ata_init(void);
bool ata_secondary_present(void);
size_t ata_secondary_size(void);
const struct ext2_storage_ops* ata_secondary_storage_ops(void);
void* ata_secondary_storage_ctx(void);
bool ata_scsi_present(void);
size_t ata_scsi_size(void);
const struct ext2_storage_ops* ata_scsi_storage_ops(void);
void* ata_scsi_storage_ctx(void);
