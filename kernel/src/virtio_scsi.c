#include "virtio_scsi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "io.h"
#include "pci.h"
#include "scsi.h"
#include "string.h"

#define VIRTIO_VENDOR_ID 0x1AF4u
#define VIRTIO_SCSI_DEVICE_ID 0x1004u

#define VIRTIO_PCI_HOST_FEATURES 0u
#define VIRTIO_PCI_GUEST_FEATURES 4u
#define VIRTIO_PCI_QUEUE_PFN 8u
#define VIRTIO_PCI_QUEUE_NUM 12u
#define VIRTIO_PCI_QUEUE_SEL 14u
#define VIRTIO_PCI_QUEUE_NOTIFY 16u
#define VIRTIO_PCI_STATUS 18u

#define VIRTIO_STATUS_ACKNOWLEDGE 1u
#define VIRTIO_STATUS_DRIVER 2u
#define VIRTIO_STATUS_DRIVER_OK 4u
#define VIRTIO_STATUS_FEATURES_OK 8u
#define VIRTIO_STATUS_FAILED 128u

#define VRING_DESC_F_NEXT 1u
#define VRING_DESC_F_WRITE 2u

#define VIRTQ_SIZE 8u
#define VIRTIO_SCSI_QUEUE_REQUEST 2u
#define VIRTIO_SCSI_S_OK 0u
#define VIRTIO_SCSI_S_BAD_TARGET 3u

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VIRTQ_SIZE];
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[VIRTQ_SIZE];
} __attribute__((packed));

struct virtio_scsi_cmd_req {
    uint8_t lun[8];
    uint64_t tag;
    uint8_t task_attr;
    uint8_t prio;
    uint8_t crn;
    uint8_t cdb[32];
} __attribute__((packed));

struct virtio_scsi_cmd_resp {
    uint32_t sense_len;
    uint32_t residual;
    uint16_t status_qualifier;
    uint8_t status;
    uint8_t response;
    uint8_t sense[96];
} __attribute__((packed));

struct virtio_scsi_queue {
    struct vring_desc desc[VIRTQ_SIZE];
    struct vring_avail avail;
    uint8_t pad[4096u - sizeof(struct vring_desc) * VIRTQ_SIZE - sizeof(struct vring_avail)];
    struct vring_used used;
} __attribute__((packed, aligned(4096)));

static struct virtio_scsi_queue g_queue;
static struct virtio_scsi_cmd_req g_req __attribute__((aligned(16)));
static struct virtio_scsi_cmd_resp g_resp __attribute__((aligned(16)));
static uint8_t g_data[4096] __attribute__((aligned(16)));
static uint16_t g_io_base;
static uint16_t g_last_used_idx;
static bool g_present;
static struct scsi_disk g_disk;

static void virtio_status_or(uint8_t value) {
    outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), (uint8_t)(inb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS)) | value));
}

static int virtio_scsi_command(void* ctx, const uint8_t* cdb, size_t cdb_len, void* data, size_t data_len, bool data_in) {
    (void)ctx;
    if (!g_present || cdb == NULL || cdb_len > sizeof(g_req.cdb) || data_len > sizeof(g_data) || (data_len != 0u && data == NULL)) {
        return -1;
    }

    memset(&g_req, 0, sizeof(g_req));
    memset(&g_resp, 0, sizeof(g_resp));
    if (data_len != 0u && !data_in) {
        memcpy(g_data, data, data_len);
    }
    g_req.lun[0] = 1u;
    g_req.lun[1] = 0u;
    g_req.lun[2] = 0x40u;
    g_req.lun[3] = 0u;
    memcpy(g_req.cdb, cdb, cdb_len);

    memset(&g_queue.desc, 0, sizeof(g_queue.desc));
    g_queue.desc[0].addr = (uint64_t)(uintptr_t)&g_req;
    g_queue.desc[0].len = sizeof(g_req);
    g_queue.desc[0].flags = VRING_DESC_F_NEXT;
    g_queue.desc[0].next = 1u;

    uint16_t resp_desc = 1u;
    if (data_len != 0u) {
        g_queue.desc[1].addr = (uint64_t)(uintptr_t)g_data;
        g_queue.desc[1].len = (uint32_t)data_len;
        g_queue.desc[1].flags = VRING_DESC_F_NEXT | (data_in ? VRING_DESC_F_WRITE : 0u);
        g_queue.desc[1].next = 2u;
        resp_desc = 2u;
    }
    g_queue.desc[resp_desc].addr = (uint64_t)(uintptr_t)&g_resp;
    g_queue.desc[resp_desc].len = sizeof(g_resp);
    g_queue.desc[resp_desc].flags = VRING_DESC_F_WRITE;
    g_queue.desc[resp_desc].next = 0u;

    g_queue.avail.ring[g_queue.avail.idx % VIRTQ_SIZE] = 0u;
    __asm__ volatile("" : : : "memory");
    ++g_queue.avail.idx;
    outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NOTIFY), VIRTIO_SCSI_QUEUE_REQUEST);

    for (uint32_t spins = 0; spins < 10000000u; ++spins) {
        if (g_queue.used.idx != g_last_used_idx) {
            g_last_used_idx = g_queue.used.idx;
            if (g_resp.response != VIRTIO_SCSI_S_OK || g_resp.status != 0u) {
                return -1;
            }
            if (data_len != 0u && data_in) {
                memcpy(data, g_data, data_len);
            }
            return 0;
        }
    }
    return -1;
}

static const struct scsi_transport g_transport = {
    .command = virtio_scsi_command,
};

static bool virtio_setup_queue(uint16_t queue_index) {
    outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_SEL), queue_index);
    uint16_t queue_size = inw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NUM));
    if (queue_size < VIRTQ_SIZE) {
        return false;
    }
    memset(&g_queue, 0, sizeof(g_queue));
    outl((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_PFN), (uint32_t)((uintptr_t)&g_queue >> 12));
    return true;
}

void virtio_scsi_init(void) {
    struct pci_device dev;
    if (g_present) {
        return;
    }
    if (!pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_SCSI_DEVICE_ID, &dev)) {
        return;
    }
    g_io_base = pci_io_bar(&dev, 0u);
    if (g_io_base == 0u) {
        return;
    }

    uint16_t command = pci_read_config16(&dev, 4u);
    command |= 0x5u;
    pci_write_config16(&dev, 4u, command);

    outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), 0u);
    virtio_status_or(VIRTIO_STATUS_ACKNOWLEDGE);
    virtio_status_or(VIRTIO_STATUS_DRIVER);
    (void)inl((uint16_t)(g_io_base + VIRTIO_PCI_HOST_FEATURES));
    outl((uint16_t)(g_io_base + VIRTIO_PCI_GUEST_FEATURES), 0u);
    virtio_status_or(VIRTIO_STATUS_FEATURES_OK);
    if ((inb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS)) & VIRTIO_STATUS_FEATURES_OK) == 0u) {
        virtio_status_or(VIRTIO_STATUS_FAILED);
        return;
    }
    if (!virtio_setup_queue(VIRTIO_SCSI_QUEUE_REQUEST)) {
        virtio_status_or(VIRTIO_STATUS_FAILED);
        return;
    }

    g_present = true;
    virtio_status_or(VIRTIO_STATUS_DRIVER_OK);
    if (scsi_disk_probe(&g_disk, &g_transport, NULL, true) != 0) {
        g_present = false;
        virtio_status_or(VIRTIO_STATUS_FAILED);
    }
}

bool virtio_scsi_present(void) {
    return g_disk.present;
}

size_t virtio_scsi_size(void) {
    return scsi_disk_size(&g_disk);
}

const struct ext2_storage_ops* virtio_scsi_storage_ops(void) {
    return scsi_disk_storage_ops();
}

void* virtio_scsi_storage_ctx(void) {
    return &g_disk;
}

