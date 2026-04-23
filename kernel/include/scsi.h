#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ext2.h"

struct scsi_transport {
    int (*command)(void* ctx, const uint8_t* cdb, size_t cdb_len, void* data, size_t data_len, bool data_in);
};

struct scsi_disk {
    bool present;
    bool writable;
    uint32_t block_size;
    uint64_t block_count;
    const struct scsi_transport* transport;
    void* transport_ctx;
};

int scsi_disk_probe(struct scsi_disk* disk, const struct scsi_transport* transport, void* transport_ctx, bool writable);
size_t scsi_disk_size(const struct scsi_disk* disk);
const struct ext2_storage_ops* scsi_disk_storage_ops(void);

