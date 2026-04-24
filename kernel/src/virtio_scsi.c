#include "virtio_scsi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "io.h"
#include "kmalloc.h"
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
#define VRING_ALIGN 4096u
#define VIRTIO_SCSI_QUEUE_REQUEST 2u
#define VIRTIO_SCSI_S_OK 0u
#define VIRTIO_SCSI_S_BAD_TARGET 3u
#define VIRTIO_SCSI_CMD_SPIN_LIMIT 200000u
#define VIRTIO_SCSI_MAX_DISKS 4u
#define VIRTIO_SCSI_TARGET_SCAN_LIMIT 8u

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[];
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
    void* raw;
    uint16_t size;
    struct vring_desc* desc;
    volatile struct vring_avail* avail;
    volatile struct vring_used* used;
};

static struct virtio_scsi_queue g_control_queue;
static struct virtio_scsi_queue g_event_queue;
static struct virtio_scsi_queue g_request_queue;
static struct virtio_scsi_cmd_req g_req __attribute__((aligned(16)));
static struct virtio_scsi_cmd_resp g_resp __attribute__((aligned(16)));
static uint8_t g_data[4096] __attribute__((aligned(16)));
static uint16_t g_io_base;
static uint16_t g_last_used_idx;
static bool g_present;

struct virtio_scsi_target {
    struct scsi_disk disk;
    uint8_t target;
    uint16_t lun;
};

static struct virtio_scsi_target g_targets[VIRTIO_SCSI_MAX_DISKS];
static size_t g_target_count;

static void virtio_status_or(uint8_t value) {
    outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), (uint8_t)(inb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS)) | value));
}

static size_t align_up_size(size_t value, size_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static size_t virtio_avail_size(uint16_t queue_size) {
    return offsetof(struct vring_avail, ring) + (size_t)queue_size * sizeof(uint16_t);
}

static size_t virtio_used_size(uint16_t queue_size) {
    return offsetof(struct vring_used, ring) + (size_t)queue_size * sizeof(struct vring_used_elem);
}

static void virtio_scsi_encode_lun(uint8_t lun_out[8], uint8_t target, uint16_t lun) {
    memset(lun_out, 0, 8u);
    lun_out[0] = 1u;
    lun_out[1] = target;
    lun_out[2] = (uint8_t)(0x40u | ((lun >> 8) & 0x3Fu));
    lun_out[3] = (uint8_t)lun;
}

static int virtio_scsi_command(void* ctx, const uint8_t* cdb, size_t cdb_len, void* data, size_t data_len, bool data_in) {
    struct virtio_scsi_target* target = (struct virtio_scsi_target*)ctx;
    if (!g_present || g_request_queue.size < 3u || cdb == NULL || cdb_len > sizeof(g_req.cdb) || data_len > sizeof(g_data) ||
        (data_len != 0u && data == NULL)) {
        return -1;
    }
    if (target == NULL) {
        return -1;
    }

    memset(&g_req, 0, sizeof(g_req));
    memset(&g_resp, 0, sizeof(g_resp));
    if (data_len != 0u && !data_in) {
        memcpy(g_data, data, data_len);
    }
    virtio_scsi_encode_lun(g_req.lun, target->target, target->lun);
    memcpy(g_req.cdb, cdb, cdb_len);

    memset(g_request_queue.desc, 0, sizeof(*g_request_queue.desc) * g_request_queue.size);
    g_request_queue.desc[0].addr = (uint64_t)(uintptr_t)&g_req;
    g_request_queue.desc[0].len = sizeof(g_req);
    g_request_queue.desc[0].flags = VRING_DESC_F_NEXT;
    g_request_queue.desc[0].next = 1u;

    if (data_len != 0u && data_in) {
        g_request_queue.desc[1].addr = (uint64_t)(uintptr_t)&g_resp;
        g_request_queue.desc[1].len = sizeof(g_resp);
        g_request_queue.desc[1].flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        g_request_queue.desc[1].next = 2u;

        g_request_queue.desc[2].addr = (uint64_t)(uintptr_t)g_data;
        g_request_queue.desc[2].len = (uint32_t)data_len;
        g_request_queue.desc[2].flags = VRING_DESC_F_WRITE;
        g_request_queue.desc[2].next = 0u;
    } else if (data_len != 0u) {
        g_request_queue.desc[1].addr = (uint64_t)(uintptr_t)g_data;
        g_request_queue.desc[1].len = (uint32_t)data_len;
        g_request_queue.desc[1].flags = VRING_DESC_F_NEXT;
        g_request_queue.desc[1].next = 2u;

        g_request_queue.desc[2].addr = (uint64_t)(uintptr_t)&g_resp;
        g_request_queue.desc[2].len = sizeof(g_resp);
        g_request_queue.desc[2].flags = VRING_DESC_F_WRITE;
        g_request_queue.desc[2].next = 0u;
    } else {
        g_request_queue.desc[1].addr = (uint64_t)(uintptr_t)&g_resp;
        g_request_queue.desc[1].len = sizeof(g_resp);
        g_request_queue.desc[1].flags = VRING_DESC_F_WRITE;
        g_request_queue.desc[1].next = 0u;
    }

    g_request_queue.avail->ring[g_request_queue.avail->idx % g_request_queue.size] = 0u;
    __asm__ volatile("" : : : "memory");
    ++g_request_queue.avail->idx;
    __asm__ volatile("" : : : "memory");
    outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NOTIFY), VIRTIO_SCSI_QUEUE_REQUEST);

    for (uint32_t spins = 0; spins < VIRTIO_SCSI_CMD_SPIN_LIMIT; ++spins) {
        uint16_t used_idx = g_request_queue.used->idx;
        if (used_idx != g_last_used_idx) {
            g_last_used_idx = used_idx;
            if (g_resp.response != VIRTIO_SCSI_S_OK || g_resp.status != 0u) {
                return -1;
            }
            if (data_len != 0u && data_in) {
                memcpy(data, g_data, data_len);
            }
            return 0;
        }
        __asm__ volatile("pause" : : : "memory");
    }
    return -1;
}

static const struct scsi_transport g_transport = {
    .command = virtio_scsi_command,
};

static bool virtio_setup_queue(struct virtio_scsi_queue* queue, uint16_t queue_index, uint16_t min_size) {
    if (queue == NULL) {
        return false;
    }
    outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_SEL), queue_index);
    uint16_t queue_size = inw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NUM));
    if (queue_size < min_size) {
        return false;
    }

    size_t desc_size = (size_t)queue_size * sizeof(struct vring_desc);
    size_t avail_off = desc_size;
    size_t avail_size = virtio_avail_size(queue_size);
    size_t used_off = align_up_size(avail_off + avail_size, VRING_ALIGN);
    size_t total_size = used_off + virtio_used_size(queue_size);
    void* raw = kmalloc_aligned(total_size, VRING_ALIGN);
    if (raw == NULL) {
        return false;
    }

    memset(raw, 0, total_size);
    memset(queue, 0, sizeof(*queue));
    queue->raw = raw;
    queue->size = queue_size;
    queue->desc = (struct vring_desc*)raw;
    queue->avail = (volatile struct vring_avail*)((uint8_t*)raw + avail_off);
    queue->used = (volatile struct vring_used*)((uint8_t*)raw + used_off);
    outl((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_PFN), (uint32_t)((uintptr_t)raw >> 12));
    return true;
}

void virtio_scsi_init(void) {
    struct pci_device dev;
    if (g_present) {
        return;
    }
    memset(g_targets, 0, sizeof(g_targets));
    g_target_count = 0u;
    if (!pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_SCSI_DEVICE_ID, &dev)) {
        return;
    }
    g_io_base = pci_io_bar(&dev, 0u);
    if (g_io_base == 0u) {
        console_write("virtio-scsi: controller has no legacy I/O BAR\n");
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
    memset(&g_control_queue, 0, sizeof(g_control_queue));
    memset(&g_event_queue, 0, sizeof(g_event_queue));
    memset(&g_request_queue, 0, sizeof(g_request_queue));
    if (!virtio_setup_queue(&g_control_queue, 0u, 1u) || !virtio_setup_queue(&g_event_queue, 1u, 1u) ||
        !virtio_setup_queue(&g_request_queue, VIRTIO_SCSI_QUEUE_REQUEST, 3u)) {
        console_write("virtio-scsi: queue setup failed\n");
        virtio_status_or(VIRTIO_STATUS_FAILED);
        return;
    }

    g_present = true;
    virtio_status_or(VIRTIO_STATUS_DRIVER_OK);
    g_last_used_idx = 0u;
    for (uint8_t target = 0; target < VIRTIO_SCSI_TARGET_SCAN_LIMIT && g_target_count < VIRTIO_SCSI_MAX_DISKS; ++target) {
        struct virtio_scsi_target* slot = &g_targets[g_target_count];
        memset(slot, 0, sizeof(*slot));
        slot->target = target;
        slot->lun = 0u;
        if (scsi_disk_probe(&slot->disk, &g_transport, slot, true) == 0) {
            ++g_target_count;
        } else if (g_target_count != 0u) {
            break;
        }
    }
    if (g_target_count == 0u) {
        console_write("virtio-scsi: controller present but no disks responded\n");
        g_present = false;
        virtio_status_or(VIRTIO_STATUS_FAILED);
    }
}

size_t virtio_scsi_disk_count(void) {
    return g_target_count;
}

bool virtio_scsi_disk_present(size_t index) {
    return index < g_target_count && g_targets[index].disk.present;
}

size_t virtio_scsi_disk_size(size_t index) {
    if (!virtio_scsi_disk_present(index)) {
        return 0u;
    }
    return scsi_disk_size(&g_targets[index].disk);
}

const struct ext2_storage_ops* virtio_scsi_disk_storage_ops(size_t index) {
    if (!virtio_scsi_disk_present(index)) {
        return NULL;
    }
    return scsi_disk_storage_ops();
}

void* virtio_scsi_disk_storage_ctx(size_t index) {
    if (!virtio_scsi_disk_present(index)) {
        return NULL;
    }
    return &g_targets[index].disk;
}

bool virtio_scsi_present(void) {
    return virtio_scsi_disk_present(0u);
}

size_t virtio_scsi_size(void) {
    return virtio_scsi_disk_size(0u);
}

const struct ext2_storage_ops* virtio_scsi_storage_ops(void) {
    return virtio_scsi_disk_storage_ops(0u);
}

void* virtio_scsi_storage_ctx(void) {
    return virtio_scsi_disk_storage_ctx(0u);
}
