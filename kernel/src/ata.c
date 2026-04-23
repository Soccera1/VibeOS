#include "ata.h"

#include <stddef.h>
#include <stdint.h>

#include "io.h"
#include "scsi.h"
#include "string.h"

#define ATA_REG_DATA 0u
#define ATA_REG_ERROR 1u
#define ATA_REG_SECCOUNT0 2u
#define ATA_REG_LBA0 3u
#define ATA_REG_LBA1 4u
#define ATA_REG_LBA2 5u
#define ATA_REG_FEATURES 1u
#define ATA_REG_BYTEL 4u
#define ATA_REG_BYTEH 5u
#define ATA_REG_HDDEVSEL 6u
#define ATA_REG_COMMAND 7u
#define ATA_REG_STATUS 7u

#define ATA_REG_ALTSTATUS 0u
#define ATA_REG_DEVICE_CONTROL 0u

#define ATA_SR_ERR 0x01u
#define ATA_SR_DRQ 0x08u
#define ATA_SR_DF 0x20u
#define ATA_SR_DRDY 0x40u
#define ATA_SR_BSY 0x80u

#define ATA_CMD_READ_PIO 0x20u
#define ATA_CMD_WRITE_PIO 0x30u
#define ATA_CMD_CACHE_FLUSH 0xE7u
#define ATA_CMD_IDENTIFY 0xECu
#define ATA_CMD_IDENTIFY_PACKET 0xA1u
#define ATA_CMD_PACKET 0xA0u

#define ATA_SECTOR_SIZE 512u
#define ATAPI_MAX_TRANSFER 4096u

struct ata_device {
    bool present;
    uint16_t io_base;
    uint16_t ctrl_base;
    bool slave;
    uint32_t sector_count;
};

static struct ata_device g_home_dev;
static struct ata_device g_scsi_packet_dev;
static struct scsi_disk g_scsi_disk;
static bool g_ata_initialized;

static uint8_t ata_status(const struct ata_device* dev) {
    return inb((uint16_t)(dev->io_base + ATA_REG_STATUS));
}

static uint8_t ata_altstatus(const struct ata_device* dev) {
    return inb((uint16_t)(dev->ctrl_base + ATA_REG_ALTSTATUS));
}

static void ata_delay_400ns(const struct ata_device* dev) {
    (void)ata_altstatus(dev);
    (void)ata_altstatus(dev);
    (void)ata_altstatus(dev);
    (void)ata_altstatus(dev);
}

static int ata_wait_not_busy(const struct ata_device* dev) {
    for (uint32_t spins = 0; spins < 1000000u; ++spins) {
        if ((ata_status(dev) & ATA_SR_BSY) == 0u) {
            return 0;
        }
    }
    return -1;
}

static int ata_wait_drq(const struct ata_device* dev) {
    for (uint32_t spins = 0; spins < 1000000u; ++spins) {
        uint8_t status = ata_status(dev);
        if (status == 0u) {
            return -1;
        }
        if ((status & ATA_SR_BSY) != 0u) {
            continue;
        }
        if ((status & (ATA_SR_ERR | ATA_SR_DF)) != 0u) {
            return -1;
        }
        if ((status & ATA_SR_DRQ) != 0u) {
            return 0;
        }
    }
    return -1;
}

static void ata_select_drive(const struct ata_device* dev, uint32_t lba) {
    outb((uint16_t)(dev->io_base + ATA_REG_HDDEVSEL),
         (uint8_t)(0xE0u | (dev->slave ? 0x10u : 0x00u) | ((lba >> 24) & 0x0Fu)));
    ata_delay_400ns(dev);
}

static int ata_identify_device(struct ata_device* dev) {
    uint16_t identify[256];

    ata_select_drive(dev, 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_SECCOUNT0), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA0), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA1), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA2), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_COMMAND), ATA_CMD_IDENTIFY);

    if (ata_status(dev) == 0u) {
        return -1;
    }
    if (ata_wait_not_busy(dev) != 0) {
        return -1;
    }
    if (inb((uint16_t)(dev->io_base + ATA_REG_LBA1)) != 0u || inb((uint16_t)(dev->io_base + ATA_REG_LBA2)) != 0u) {
        return -1;
    }
    if (ata_wait_drq(dev) != 0) {
        return -1;
    }

    insw((uint16_t)(dev->io_base + ATA_REG_DATA), identify, 256u);
    dev->sector_count = (uint32_t)identify[60] | ((uint32_t)identify[61] << 16);
    dev->present = dev->sector_count != 0u;
    return dev->present ? 0 : -1;
}

static int ata_identify_packet_device(struct ata_device* dev) {
    uint16_t identify[256];

    ata_select_drive(dev, 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_SECCOUNT0), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA0), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA1), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA2), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_COMMAND), ATA_CMD_IDENTIFY_PACKET);

    if (ata_status(dev) == 0u || ata_wait_not_busy(dev) != 0 || ata_wait_drq(dev) != 0) {
        return -1;
    }

    insw((uint16_t)(dev->io_base + ATA_REG_DATA), identify, 256u);
    dev->sector_count = 0u;
    dev->present = true;
    return 0;
}

static int atapi_packet_command(void* ctx, const uint8_t* cdb, size_t cdb_len, void* data, size_t data_len, bool data_in) {
    struct ata_device* dev = (struct ata_device*)ctx;
    uint8_t packet[12];

    if (dev == NULL || !dev->present || cdb == NULL || cdb_len > sizeof(packet) || data_len > ATAPI_MAX_TRANSFER ||
        (!data_in && data_len != 0u)) {
        return -1;
    }

    memset(packet, 0, sizeof(packet));
    memcpy(packet, cdb, cdb_len);

    ata_select_drive(dev, 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_FEATURES), 0u);
    outb((uint16_t)(dev->io_base + ATA_REG_BYTEL), (uint8_t)(data_len & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_BYTEH), (uint8_t)((data_len >> 8) & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_COMMAND), ATA_CMD_PACKET);
    if (ata_wait_drq(dev) != 0) {
        return -1;
    }

    outsw((uint16_t)(dev->io_base + ATA_REG_DATA), packet, sizeof(packet) / sizeof(uint16_t));
    if (data_len == 0u) {
        return ata_wait_not_busy(dev);
    }
    if (ata_wait_drq(dev) != 0) {
        return -1;
    }

    size_t transfer = (size_t)inb((uint16_t)(dev->io_base + ATA_REG_BYTEL)) |
                      ((size_t)inb((uint16_t)(dev->io_base + ATA_REG_BYTEH)) << 8);
    if (transfer > data_len) {
        return -1;
    }
    if ((transfer & 1u) != 0u) {
        return -1;
    }
    if (transfer != 0u) {
        insw((uint16_t)(dev->io_base + ATA_REG_DATA), data, (uint32_t)(transfer / sizeof(uint16_t)));
    }
    return ata_wait_not_busy(dev);
}

static const struct scsi_transport g_atapi_transport = {
    .command = atapi_packet_command,
};

static int ata_read_sector(const struct ata_device* dev, uint32_t lba, void* buf) {
    if (dev == NULL || !dev->present || buf == NULL || lba >= dev->sector_count) {
        return -1;
    }

    ata_select_drive(dev, lba);
    outb((uint16_t)(dev->io_base + ATA_REG_SECCOUNT0), 1u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA0), (uint8_t)(lba & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_LBA1), (uint8_t)((lba >> 8) & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_LBA2), (uint8_t)((lba >> 16) & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_COMMAND), ATA_CMD_READ_PIO);
    if (ata_wait_drq(dev) != 0) {
        return -1;
    }

    insw((uint16_t)(dev->io_base + ATA_REG_DATA), buf, ATA_SECTOR_SIZE / sizeof(uint16_t));
    ata_delay_400ns(dev);
    return 0;
}

static int ata_flush_cache(const struct ata_device* dev) {
    outb((uint16_t)(dev->io_base + ATA_REG_COMMAND), ATA_CMD_CACHE_FLUSH);
    return ata_wait_not_busy(dev);
}

static int ata_write_sector(const struct ata_device* dev, uint32_t lba, const void* buf) {
    if (dev == NULL || !dev->present || buf == NULL || lba >= dev->sector_count) {
        return -1;
    }

    ata_select_drive(dev, lba);
    outb((uint16_t)(dev->io_base + ATA_REG_SECCOUNT0), 1u);
    outb((uint16_t)(dev->io_base + ATA_REG_LBA0), (uint8_t)(lba & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_LBA1), (uint8_t)((lba >> 8) & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_LBA2), (uint8_t)((lba >> 16) & 0xFFu));
    outb((uint16_t)(dev->io_base + ATA_REG_COMMAND), ATA_CMD_WRITE_PIO);
    if (ata_wait_drq(dev) != 0) {
        return -1;
    }

    outsw((uint16_t)(dev->io_base + ATA_REG_DATA), buf, ATA_SECTOR_SIZE / sizeof(uint16_t));
    ata_delay_400ns(dev);
    return ata_flush_cache(dev);
}

static int ata_storage_read(void* ctx, uint64_t offset, void* buf, size_t len) {
    struct ata_device* dev = (struct ata_device*)ctx;
    uint8_t sector[ATA_SECTOR_SIZE];
    uint8_t* out = (uint8_t*)buf;

    if (dev == NULL || !dev->present || buf == NULL) {
        return -1;
    }
    if (offset + len < offset || offset + len > (uint64_t)dev->sector_count * ATA_SECTOR_SIZE) {
        return -1;
    }

    while (len > 0) {
        uint32_t lba = (uint32_t)(offset / ATA_SECTOR_SIZE);
        size_t sector_off = (size_t)(offset % ATA_SECTOR_SIZE);
        size_t chunk = ATA_SECTOR_SIZE - sector_off;
        if (chunk > len) {
            chunk = len;
        }

        if (sector_off == 0u && chunk == ATA_SECTOR_SIZE) {
            if (ata_read_sector(dev, lba, out) != 0) {
                return -1;
            }
        } else {
            if (ata_read_sector(dev, lba, sector) != 0) {
                return -1;
            }
            for (size_t i = 0; i < chunk; ++i) {
                out[i] = sector[sector_off + i];
            }
        }

        out += chunk;
        offset += chunk;
        len -= chunk;
    }

    return 0;
}

static int ata_storage_write(void* ctx, uint64_t offset, const void* buf, size_t len) {
    struct ata_device* dev = (struct ata_device*)ctx;
    uint8_t sector[ATA_SECTOR_SIZE];
    const uint8_t* in = (const uint8_t*)buf;

    if (dev == NULL || !dev->present || (buf == NULL && len != 0u)) {
        return -1;
    }
    if (offset + len < offset || offset + len > (uint64_t)dev->sector_count * ATA_SECTOR_SIZE) {
        return -1;
    }

    while (len > 0) {
        uint32_t lba = (uint32_t)(offset / ATA_SECTOR_SIZE);
        size_t sector_off = (size_t)(offset % ATA_SECTOR_SIZE);
        size_t chunk = ATA_SECTOR_SIZE - sector_off;
        if (chunk > len) {
            chunk = len;
        }

        if (sector_off == 0u && chunk == ATA_SECTOR_SIZE) {
            if (ata_write_sector(dev, lba, in) != 0) {
                return -1;
            }
        } else {
            if (ata_read_sector(dev, lba, sector) != 0) {
                return -1;
            }
            for (size_t i = 0; i < chunk; ++i) {
                sector[sector_off + i] = in[i];
            }
            if (ata_write_sector(dev, lba, sector) != 0) {
                return -1;
            }
        }

        in += chunk;
        offset += chunk;
        len -= chunk;
    }

    return 0;
}

static const struct ext2_storage_ops g_ata_storage_ops = {
    .read = ata_storage_read,
    .write = ata_storage_write,
};

void ata_init(void) {
    if (g_ata_initialized) {
        return;
    }
    g_ata_initialized = true;

    static const struct {
        uint16_t io_base;
        uint16_t ctrl_base;
        bool slave;
    } candidates[] = {
        {0x1F0u, 0x3F6u, true},
        {0x170u, 0x376u, false},
        {0x170u, 0x376u, true},
    };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        struct ata_device dev;
        dev.present = false;
        dev.io_base = candidates[i].io_base;
        dev.ctrl_base = candidates[i].ctrl_base;
        dev.slave = candidates[i].slave;
        dev.sector_count = 0u;
        if (!g_home_dev.present && ata_identify_device(&dev) == 0) {
            g_home_dev = dev;
        }
    }

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        struct ata_device dev;
        dev.present = false;
        dev.io_base = candidates[i].io_base;
        dev.ctrl_base = candidates[i].ctrl_base;
        dev.slave = candidates[i].slave;
        dev.sector_count = 0u;
        if (ata_identify_packet_device(&dev) == 0 &&
            scsi_disk_probe(&g_scsi_disk, &g_atapi_transport, &dev, false) == 0) {
            g_scsi_packet_dev = dev;
            g_scsi_disk.transport_ctx = &g_scsi_packet_dev;
            return;
        }
    }
}

bool ata_secondary_present(void) {
    return g_home_dev.present;
}

size_t ata_secondary_size(void) {
    return (size_t)g_home_dev.sector_count * ATA_SECTOR_SIZE;
}

const struct ext2_storage_ops* ata_secondary_storage_ops(void) {
    return &g_ata_storage_ops;
}

void* ata_secondary_storage_ctx(void) {
    return &g_home_dev;
}

bool ata_scsi_present(void) {
    return g_scsi_disk.present;
}

size_t ata_scsi_size(void) {
    return scsi_disk_size(&g_scsi_disk);
}

const struct ext2_storage_ops* ata_scsi_storage_ops(void) {
    return scsi_disk_storage_ops();
}

void* ata_scsi_storage_ctx(void) {
    return &g_scsi_disk;
}
