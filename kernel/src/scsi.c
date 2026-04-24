#include "scsi.h"

#include <stddef.h>
#include <stdint.h>

#include "string.h"

#define SCSI_OP_TEST_UNIT_READY 0x00u
#define SCSI_OP_REQUEST_SENSE 0x03u
#define SCSI_OP_INQUIRY 0x12u
#define SCSI_OP_READ_CAPACITY_10 0x25u
#define SCSI_OP_READ_10 0x28u
#define SCSI_OP_WRITE_10 0x2Au

#define SCSI_SECTOR_SCRATCH_MAX 4096u

static uint32_t be32_load(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void be32_store(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int scsi_probe_retry(const struct scsi_transport* transport, void* transport_ctx, const uint8_t* cdb, size_t cdb_len, void* data,
                            size_t data_len, bool data_in) {
    if (transport->command(transport_ctx, cdb, cdb_len, data, data_len, data_in) == 0) {
        return 0;
    }

    uint8_t sense_cdb[6] = { 0 };
    uint8_t sense[18];
    memset(sense, 0, sizeof(sense));
    sense_cdb[0] = SCSI_OP_REQUEST_SENSE;
    sense_cdb[4] = sizeof(sense);
    (void)transport->command(transport_ctx, sense_cdb, sizeof(sense_cdb), sense, sizeof(sense), true);

    return transport->command(transport_ctx, cdb, cdb_len, data, data_len, data_in);
}

static int scsi_rw_blocks(struct scsi_disk* disk, bool write, uint64_t lba, uint16_t blocks, void* data) {
    uint8_t cdb[10];

    if (disk == NULL || !disk->present || disk->transport == NULL || disk->transport->command == NULL ||
        data == NULL || blocks == 0u || lba > 0xFFFFFFFFull || lba + blocks > disk->block_count) {
        return -1;
    }
    if (write && !disk->writable) {
        return -1;
    }

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = write ? SCSI_OP_WRITE_10 : SCSI_OP_READ_10;
    be32_store(&cdb[2], (uint32_t)lba);
    cdb[7] = (uint8_t)(blocks >> 8);
    cdb[8] = (uint8_t)blocks;
    return disk->transport->command(disk->transport_ctx, cdb, sizeof(cdb), data,
                                    (size_t)blocks * disk->block_size, !write);
}

int scsi_disk_probe(struct scsi_disk* disk, const struct scsi_transport* transport, void* transport_ctx, bool writable) {
    uint8_t inquiry[36];
    uint8_t capacity[8];
    uint8_t cdb[10];

    if (disk == NULL || transport == NULL || transport->command == NULL) {
        return -1;
    }
    memset(disk, 0, sizeof(*disk));

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_OP_INQUIRY;
    cdb[4] = sizeof(inquiry);
    if (scsi_probe_retry(transport, transport_ctx, cdb, 6u, inquiry, sizeof(inquiry), true) != 0) {
        return -1;
    }

    uint8_t peripheral = inquiry[0] & 0x1Fu;
    if (peripheral != 0x00u && peripheral != 0x05u) {
        return -1;
    }

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_OP_TEST_UNIT_READY;
    (void)scsi_probe_retry(transport, transport_ctx, cdb, 6u, NULL, 0u, true);

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_OP_READ_CAPACITY_10;
    if (scsi_probe_retry(transport, transport_ctx, cdb, sizeof(cdb), capacity, sizeof(capacity), true) != 0) {
        return -1;
    }

    uint32_t last_lba = be32_load(&capacity[0]);
    uint32_t block_size = be32_load(&capacity[4]);
    if (block_size == 0u || block_size > SCSI_SECTOR_SCRATCH_MAX) {
        return -1;
    }

    disk->present = true;
    disk->writable = writable && peripheral == 0x00u;
    disk->block_size = block_size;
    disk->block_count = (uint64_t)last_lba + 1u;
    disk->transport = transport;
    disk->transport_ctx = transport_ctx;
    return 0;
}

size_t scsi_disk_size(const struct scsi_disk* disk) {
    if (disk == NULL || !disk->present) {
        return 0;
    }
    return (size_t)(disk->block_count * disk->block_size);
}

static int scsi_storage_read(void* ctx, uint64_t offset, void* buf, size_t len) {
    struct scsi_disk* disk = (struct scsi_disk*)ctx;
    uint8_t sector[SCSI_SECTOR_SCRATCH_MAX];
    uint8_t* out = (uint8_t*)buf;

    if (disk == NULL || !disk->present || buf == NULL || disk->block_size == 0u) {
        return -1;
    }
    if (offset + len < offset || offset + len > (uint64_t)scsi_disk_size(disk)) {
        return -1;
    }

    while (len > 0) {
        uint64_t lba = offset / disk->block_size;
        size_t sector_off = (size_t)(offset % disk->block_size);
        size_t chunk = disk->block_size - sector_off;
        if (chunk > len) {
            chunk = len;
        }

        if (sector_off == 0u && chunk == disk->block_size) {
            if (scsi_rw_blocks(disk, false, lba, 1u, out) != 0) {
                return -1;
            }
        } else {
            if (scsi_rw_blocks(disk, false, lba, 1u, sector) != 0) {
                return -1;
            }
            memcpy(out, sector + sector_off, chunk);
        }

        out += chunk;
        offset += chunk;
        len -= chunk;
    }
    return 0;
}

static int scsi_storage_write(void* ctx, uint64_t offset, const void* buf, size_t len) {
    struct scsi_disk* disk = (struct scsi_disk*)ctx;
    uint8_t sector[SCSI_SECTOR_SCRATCH_MAX];
    const uint8_t* in = (const uint8_t*)buf;

    if (disk == NULL || !disk->present || !disk->writable || (buf == NULL && len != 0u) || disk->block_size == 0u) {
        return -1;
    }
    if (offset + len < offset || offset + len > (uint64_t)scsi_disk_size(disk)) {
        return -1;
    }

    while (len > 0) {
        uint64_t lba = offset / disk->block_size;
        size_t sector_off = (size_t)(offset % disk->block_size);
        size_t chunk = disk->block_size - sector_off;
        if (chunk > len) {
            chunk = len;
        }

        if (sector_off == 0u && chunk == disk->block_size) {
            if (scsi_rw_blocks(disk, true, lba, 1u, (void*)in) != 0) {
                return -1;
            }
        } else {
            if (scsi_rw_blocks(disk, false, lba, 1u, sector) != 0) {
                return -1;
            }
            memcpy(sector + sector_off, in, chunk);
            if (scsi_rw_blocks(disk, true, lba, 1u, sector) != 0) {
                return -1;
            }
        }

        in += chunk;
        offset += chunk;
        len -= chunk;
    }
    return 0;
}

static const struct ext2_storage_ops g_scsi_storage_ops = {
    .read = scsi_storage_read,
    .write = scsi_storage_write,
};

const struct ext2_storage_ops* scsi_disk_storage_ops(void) {
    return &g_scsi_storage_ops;
}
