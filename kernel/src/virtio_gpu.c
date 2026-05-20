#include "virtio_gpu.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "io.h"
#include "kmalloc.h"
#include "pci.h"
#include "string.h"

#define VIRTIO_VENDOR_ID 0x1AF4u
#define VIRTIO_GPU_MODERN_DEVICE_ID 0x1050u
#define VIRTIO_GPU_TRANSITIONAL_DEVICE_ID 0x1010u

#define VIRTIO_PCI_HOST_FEATURES 0u
#define VIRTIO_PCI_GUEST_FEATURES 4u
#define VIRTIO_PCI_QUEUE_PFN 8u
#define VIRTIO_PCI_QUEUE_NUM 12u
#define VIRTIO_PCI_QUEUE_SEL 14u
#define VIRTIO_PCI_QUEUE_NOTIFY 16u
#define VIRTIO_PCI_STATUS 18u
#define VIRTIO_PCI_ISR 19u
#define VIRTIO_PCI_CONFIG 20u

#define VIRTIO_STATUS_ACKNOWLEDGE 1u
#define VIRTIO_STATUS_DRIVER 2u
#define VIRTIO_STATUS_DRIVER_OK 4u
#define VIRTIO_STATUS_FEATURES_OK 8u
#define VIRTIO_STATUS_FAILED 128u

#define VIRTIO_PCI_CAP_COMMON_CFG 1u
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2u
#define VIRTIO_PCI_CAP_ISR_CFG 3u
#define VIRTIO_PCI_CAP_DEVICE_CFG 4u

#define VRING_DESC_F_NEXT 1u
#define VRING_DESC_F_WRITE 2u
#define VRING_ALIGN 4096u

#define VIRTIO_GPU_QUEUE_CONTROL 0u
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO 0x0100u
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D 0x0101u
#define VIRTIO_GPU_CMD_RESOURCE_UNREF 0x0102u
#define VIRTIO_GPU_CMD_SET_SCANOUT 0x0103u
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH 0x0104u
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D 0x0105u
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106u
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING 0x0107u
#define VIRTIO_GPU_RESP_OK_NODATA 0x1100u
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO 0x1101u

#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM 2u
#define VIRTIO_GPU_RESOURCE_ID_BASE 1u
#define VIRTIO_GPU_MAX_WIDTH 4096u
#define VIRTIO_GPU_MAX_HEIGHT 2160u
#define VIRTIO_GPU_DEFAULT_WIDTH 1024u
#define VIRTIO_GPU_DEFAULT_HEIGHT 768u
#define VIRTIO_GPU_CMD_SPIN_LIMIT 200000u
#define VIRTIO_GPU_EVENT_DISPLAY 1u
#define VIRTIO_GPU_RESIZE_STABLE_POLLS 3u

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

struct virtio_gpu_queue {
    void* raw;
    uint16_t size;
    uint16_t next_desc;
    struct vring_desc* desc;
    volatile struct vring_avail* avail;
    volatile struct vring_used* used;
    uint16_t last_used_idx;
};

struct virtio_gpu_ctrl_hdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint8_t ring_idx;
    uint8_t padding[3];
} __attribute__((packed));

struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_display_one {
    struct virtio_gpu_rect rect;
    uint32_t enabled;
    uint32_t flags;
} __attribute__((packed));

struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_display_one displays[16];
} __attribute__((packed));

struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_resource_unref {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect rect;
    uint32_t scanout_id;
    uint32_t resource_id;
} __attribute__((packed));

struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect rect;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect rect;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    struct virtio_gpu_mem_entry entry;
} __attribute__((packed));

static struct virtio_gpu_queue g_control_queue;
static uint16_t g_io_base;
static volatile uint8_t* g_common_cfg;
static volatile uint8_t* g_notify_cfg;
static volatile uint8_t* g_isr_cfg;
static volatile uint8_t* g_device_cfg;
static uint32_t g_notify_off_multiplier;
static bool g_modern;
static bool g_present;
static bool g_adaptive;
static uint32_t g_resource_id;
static uint32_t g_next_resource_id = VIRTIO_GPU_RESOURCE_ID_BASE;
static uint32_t g_width;
static uint32_t g_height;
static uint8_t* g_framebuffer;
static uint32_t g_poll_counter;
static uint32_t g_pending_width;
static uint32_t g_pending_height;
static uint8_t g_pending_stable_polls;
static bool g_failure_reported;
static struct virtio_gpu_ctrl_hdr g_response __attribute__((aligned(16)));

static uint16_t mmio_read16(volatile uint8_t* base, uint32_t offset) {
    return *(volatile uint16_t*)(uintptr_t)(base + offset);
}

static uint32_t mmio_read32(volatile uint8_t* base, uint32_t offset) {
    return *(volatile uint32_t*)(uintptr_t)(base + offset);
}

static void mmio_write16(volatile uint8_t* base, uint32_t offset, uint16_t value) {
    *(volatile uint16_t*)(uintptr_t)(base + offset) = value;
}

static void mmio_write32(volatile uint8_t* base, uint32_t offset, uint32_t value) {
    *(volatile uint32_t*)(uintptr_t)(base + offset) = value;
}

static void mmio_write64(volatile uint8_t* base, uint32_t offset, uint64_t value) {
    mmio_write32(base, offset, (uint32_t)value);
    mmio_write32(base, offset + 4u, (uint32_t)(value >> 32));
}

static uint32_t virtio_gpu_config_read32(uint8_t offset) {
    if (g_modern) {
        return mmio_read32(g_device_cfg, offset);
    }
    return inl((uint16_t)(g_io_base + VIRTIO_PCI_CONFIG + offset));
}

static void virtio_gpu_config_write32(uint8_t offset, uint32_t value) {
    if (g_modern) {
        mmio_write32(g_device_cfg, offset, value);
        return;
    }
    outl((uint16_t)(g_io_base + VIRTIO_PCI_CONFIG + offset), value);
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

static void virtio_status_or(uint8_t value) {
    if (g_modern) {
        g_common_cfg[20] = (uint8_t)(g_common_cfg[20] | value);
        return;
    }
    outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), (uint8_t)(inb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS)) | value));
}

static bool virtio_setup_queue(struct virtio_gpu_queue* queue, uint16_t queue_index, uint16_t min_size) {
    if (g_modern) {
        mmio_write16(g_common_cfg, 22u, queue_index);
    } else {
        outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_SEL), queue_index);
    }
    uint16_t queue_size = g_modern ? mmio_read16(g_common_cfg, 24u) : inw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NUM));
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
    if (g_modern) {
        mmio_write16(g_common_cfg, 24u, queue_size);
        mmio_write64(g_common_cfg, 32u, (uint64_t)(uintptr_t)queue->desc);
        mmio_write64(g_common_cfg, 40u, (uint64_t)(uintptr_t)queue->avail);
        mmio_write64(g_common_cfg, 48u, (uint64_t)(uintptr_t)queue->used);
        mmio_write16(g_common_cfg, 26u, 0u);
        mmio_write16(g_common_cfg, 28u, 1u);
    } else {
        outl((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_PFN), (uint32_t)((uintptr_t)raw >> 12));
    }
    return true;
}

static void virtio_notify_queue(uint16_t queue_index) {
    if (g_modern) {
        mmio_write16(g_common_cfg, 22u, queue_index);
        uint16_t notify_off = mmio_read16(g_common_cfg, 30u);
        volatile uint8_t* addr = g_notify_cfg + (uint32_t)notify_off * g_notify_off_multiplier;
        *(volatile uint16_t*)(uintptr_t)addr = queue_index;
        return;
    }
    outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NOTIFY), queue_index);
}

static volatile uint8_t* virtio_cap_ptr(const struct pci_device* dev, const struct pci_virtio_cap* cap) {
    if (cap == NULL || cap->bar >= 6u) {
        return NULL;
    }
    uint32_t base = pci_mem_bar(dev, cap->bar);
    if (base == 0u || cap->offset >= 0x10000000u) {
        return NULL;
    }
    return (volatile uint8_t*)(uintptr_t)(base + cap->offset);
}

static bool virtio_gpu_setup_modern(const struct pci_device* dev) {
    struct pci_virtio_cap common;
    struct pci_virtio_cap notify;
    struct pci_virtio_cap isr;
    struct pci_virtio_cap device;
    if (!pci_find_virtio_cap(dev, VIRTIO_PCI_CAP_COMMON_CFG, &common) ||
        !pci_find_virtio_cap(dev, VIRTIO_PCI_CAP_NOTIFY_CFG, &notify) ||
        !pci_find_virtio_cap(dev, VIRTIO_PCI_CAP_ISR_CFG, &isr) ||
        !pci_find_virtio_cap(dev, VIRTIO_PCI_CAP_DEVICE_CFG, &device)) {
        return false;
    }

    g_common_cfg = virtio_cap_ptr(dev, &common);
    g_notify_cfg = virtio_cap_ptr(dev, &notify);
    g_isr_cfg = virtio_cap_ptr(dev, &isr);
    g_device_cfg = virtio_cap_ptr(dev, &device);
    g_notify_off_multiplier = notify.notify_off_multiplier;
    if (g_common_cfg == NULL || g_notify_cfg == NULL || g_isr_cfg == NULL || g_device_cfg == NULL ||
        g_notify_off_multiplier == 0u) {
        return false;
    }

    g_modern = true;
    g_common_cfg[20] = 0u;
    virtio_status_or(VIRTIO_STATUS_ACKNOWLEDGE);
    virtio_status_or(VIRTIO_STATUS_DRIVER);
    mmio_write32(g_common_cfg, 0u, 0u);
    (void)mmio_read32(g_common_cfg, 4u);
    mmio_write32(g_common_cfg, 8u, 0u);
    mmio_write32(g_common_cfg, 12u, 0u);
    virtio_status_or(VIRTIO_STATUS_FEATURES_OK);
    if ((g_common_cfg[20] & VIRTIO_STATUS_FEATURES_OK) == 0u) {
        g_modern = false;
        return false;
    }
    return true;
}

static void init_header(struct virtio_gpu_ctrl_hdr* hdr, uint32_t type) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->type = type;
}

static uint16_t virtio_gpu_alloc_desc_pair(void) {
    uint16_t head = g_control_queue.next_desc;
    uint16_t tail = (uint16_t)(head + 1u);
    if (tail >= g_control_queue.size) {
        tail = 0u;
    }

    g_control_queue.next_desc = (uint16_t)(tail + 1u);
    if (g_control_queue.next_desc >= g_control_queue.size) {
        g_control_queue.next_desc = 0u;
    }
    return head;
}

static bool virtio_gpu_command(void* request, size_t request_size, void* response, size_t response_size, uint32_t ok_type) {
    if (!g_adaptive || g_control_queue.size < 2u || request == NULL || request_size == 0u || response == NULL ||
        response_size < sizeof(struct virtio_gpu_ctrl_hdr) || request_size > UINT32_MAX || response_size > UINT32_MAX) {
        return false;
    }

    memset(response, 0, response_size);
    uint16_t head = virtio_gpu_alloc_desc_pair();
    uint16_t tail = (uint16_t)(head + 1u);
    if (tail >= g_control_queue.size) {
        tail = 0u;
    }

    g_control_queue.desc[tail].addr = (uint64_t)(uintptr_t)response;
    g_control_queue.desc[tail].len = (uint32_t)response_size;
    g_control_queue.desc[tail].flags = VRING_DESC_F_WRITE;
    g_control_queue.desc[tail].next = 0u;
    g_control_queue.desc[head].addr = (uint64_t)(uintptr_t)request;
    g_control_queue.desc[head].len = (uint32_t)request_size;
    g_control_queue.desc[head].flags = VRING_DESC_F_NEXT;
    g_control_queue.desc[head].next = tail;

    __asm__ volatile("mfence" : : : "memory");
    g_control_queue.avail->ring[g_control_queue.avail->idx % g_control_queue.size] = head;
    __asm__ volatile("mfence" : : : "memory");
    ++g_control_queue.avail->idx;
    __asm__ volatile("mfence" : : : "memory");
    virtio_notify_queue(VIRTIO_GPU_QUEUE_CONTROL);

    for (uint32_t spins = 0; spins < VIRTIO_GPU_CMD_SPIN_LIMIT; ++spins) {
        if (g_control_queue.last_used_idx != g_control_queue.used->idx) {
            ++g_control_queue.last_used_idx;
            const struct virtio_gpu_ctrl_hdr* hdr = (const struct virtio_gpu_ctrl_hdr*)response;
            return hdr->type == ok_type;
        }
        __asm__ volatile("pause" : : : "memory");
    }
    g_adaptive = false;
    if (!g_failure_reported) {
        g_failure_reported = true;
        console_write("virtio-gpu: command timed out; adaptive framebuffer disabled\n");
    }
    return false;
}

static bool query_display_size(uint32_t* width_out, uint32_t* height_out) {
    struct virtio_gpu_ctrl_hdr req;
    struct virtio_gpu_resp_display_info resp;
    init_header(&req, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    if (!virtio_gpu_command(&req, sizeof(req), &resp, sizeof(resp), VIRTIO_GPU_RESP_OK_DISPLAY_INFO)) {
        return false;
    }

    uint32_t width = resp.displays[0].rect.width;
    uint32_t height = resp.displays[0].rect.height;
    if (resp.displays[0].enabled == 0u || width == 0u || height == 0u) {
        width = VIRTIO_GPU_DEFAULT_WIDTH;
        height = VIRTIO_GPU_DEFAULT_HEIGHT;
    }
    if (width > VIRTIO_GPU_MAX_WIDTH) {
        width = VIRTIO_GPU_MAX_WIDTH;
    }
    if (height > VIRTIO_GPU_MAX_HEIGHT) {
        height = VIRTIO_GPU_MAX_HEIGHT;
    }
    *width_out = width;
    *height_out = height;
    return true;
}

static void destroy_scanout(uint32_t resource_id, uint8_t* framebuffer);

static bool create_scanout(uint32_t width, uint32_t height, uint32_t* resource_id_out, uint8_t** framebuffer_out,
                           size_t* framebuffer_size_out) {
    size_t size = (size_t)width * height * 4u;
    uint8_t* framebuffer = kmalloc_aligned(size, 4096u);
    if (framebuffer == NULL) {
        return false;
    }
    memset(framebuffer, 0, size);

    uint32_t resource_id = g_next_resource_id++;

    struct virtio_gpu_resource_create_2d create;
    init_header(&create.hdr, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    create.resource_id = resource_id;
    create.format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
    create.width = width;
    create.height = height;
    if (!virtio_gpu_command(&create, sizeof(create), &g_response, sizeof(g_response), VIRTIO_GPU_RESP_OK_NODATA)) {
        kfree_aligned(framebuffer);
        return false;
    }

    struct virtio_gpu_resource_attach_backing attach;
    init_header(&attach.hdr, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    attach.resource_id = resource_id;
    attach.nr_entries = 1u;
    attach.entry.addr = (uint64_t)(uintptr_t)framebuffer;
    attach.entry.length = (uint32_t)size;
    attach.entry.padding = 0u;
    if (!virtio_gpu_command(&attach, sizeof(attach), &g_response, sizeof(g_response), VIRTIO_GPU_RESP_OK_NODATA)) {
        destroy_scanout(resource_id, framebuffer);
        return false;
    }

    struct virtio_gpu_set_scanout scanout;
    init_header(&scanout.hdr, VIRTIO_GPU_CMD_SET_SCANOUT);
    scanout.rect.x = 0u;
    scanout.rect.y = 0u;
    scanout.rect.width = width;
    scanout.rect.height = height;
    scanout.scanout_id = 0u;
    scanout.resource_id = resource_id;
    if (!virtio_gpu_command(&scanout, sizeof(scanout), &g_response, sizeof(g_response), VIRTIO_GPU_RESP_OK_NODATA)) {
        destroy_scanout(resource_id, framebuffer);
        return false;
    }

    *resource_id_out = resource_id;
    *framebuffer_out = framebuffer;
    *framebuffer_size_out = size;
    return true;
}

static void destroy_scanout(uint32_t resource_id, uint8_t* framebuffer) {
    if (resource_id != 0u) {
        struct virtio_gpu_resource_unref unref;
        init_header(&unref.hdr, VIRTIO_GPU_CMD_RESOURCE_UNREF);
        unref.resource_id = resource_id;
        unref.padding = 0u;
        (void)virtio_gpu_command(&unref, sizeof(unref), &g_response, sizeof(g_response), VIRTIO_GPU_RESP_OK_NODATA);
    }
    kfree_aligned(framebuffer);
}

static void virtio_gpu_flush_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    if (!g_adaptive || g_resource_id == 0u || width == 0u || height == 0u) {
        return;
    }

    struct virtio_gpu_transfer_to_host_2d transfer;
    init_header(&transfer.hdr, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    transfer.rect.x = x;
    transfer.rect.y = y;
    transfer.rect.width = width;
    transfer.rect.height = height;
    transfer.offset = (uint64_t)((size_t)y * g_width * 4u + (size_t)x * 4u);
    transfer.resource_id = g_resource_id;
    transfer.padding = 0u;
    (void)virtio_gpu_command(&transfer, sizeof(transfer), &g_response, sizeof(g_response), VIRTIO_GPU_RESP_OK_NODATA);

    struct virtio_gpu_resource_flush flush;
    init_header(&flush.hdr, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    flush.rect.x = x;
    flush.rect.y = y;
    flush.rect.width = width;
    flush.rect.height = height;
    flush.resource_id = g_resource_id;
    flush.padding = 0u;
    (void)virtio_gpu_command(&flush, sizeof(flush), &g_response, sizeof(g_response), VIRTIO_GPU_RESP_OK_NODATA);
}

static bool apply_resize(uint32_t width, uint32_t height) {
    if (width == g_width && height == g_height && g_resource_id != 0u) {
        return true;
    }

    uint32_t new_resource_id = 0u;
    uint8_t* new_framebuffer = NULL;
    size_t new_size = 0u;
    if (!create_scanout(width, height, &new_resource_id, &new_framebuffer, &new_size)) {
        return false;
    }

    struct console_framebuffer_info info;
    memset(&info, 0, sizeof(info));
    info.present = true;
    info.phys_addr = (uint64_t)(uintptr_t)new_framebuffer;
    info.pitch = width * 4u;
    info.width = width;
    info.height = height;
    info.size = (uint32_t)new_size;
    info.bpp = 32u;
    info.red_offset = 16u;
    info.red_length = 8u;
    info.green_offset = 8u;
    info.green_length = 8u;
    info.blue_offset = 0u;
    info.blue_length = 8u;
    info.transp_offset = 24u;
    info.transp_length = 8u;

    uint32_t old_resource_id = g_resource_id;
    uint8_t* old_framebuffer = g_framebuffer;
    g_resource_id = new_resource_id;
    g_framebuffer = new_framebuffer;
    g_width = width;
    g_height = height;
    if (!console_configure_framebuffer(&info, virtio_gpu_flush_rect)) {
        g_resource_id = old_resource_id;
        g_framebuffer = old_framebuffer;
        destroy_scanout(new_resource_id, new_framebuffer);
        return false;
    }

    destroy_scanout(old_resource_id, old_framebuffer);
    g_pending_width = 0u;
    g_pending_height = 0u;
    g_pending_stable_polls = 0u;
    return true;
}

static void stage_resize(uint32_t width, uint32_t height) {
    if (width == g_width && height == g_height) {
        g_pending_width = 0u;
        g_pending_height = 0u;
        g_pending_stable_polls = 0u;
        return;
    }

    if (width != g_pending_width || height != g_pending_height) {
        g_pending_width = width;
        g_pending_height = height;
        g_pending_stable_polls = 1u;
        return;
    }

    if (g_pending_stable_polls < VIRTIO_GPU_RESIZE_STABLE_POLLS) {
        ++g_pending_stable_polls;
        return;
    }

    (void)apply_resize(width, height);
}

void virtio_gpu_init(void) {
    struct pci_device dev;
    if (g_present) {
        return;
    }

    if (!pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_GPU_TRANSITIONAL_DEVICE_ID, &dev)) {
        if (!pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_GPU_MODERN_DEVICE_ID, &dev)) {
            return;
        }
    }

    uint16_t command = pci_read_config16(&dev, 4u);
    command |= 0x7u;
    pci_write_config16(&dev, 4u, command);

    g_present = true;
    g_io_base = pci_io_bar(&dev, 0u);
    if (g_io_base == 0u && !virtio_gpu_setup_modern(&dev)) {
        console_write("virtio-gpu: controller present (boot framebuffer only)\n");
        return;
    }

    if (!g_modern) {
        outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), 0u);
        virtio_status_or(VIRTIO_STATUS_ACKNOWLEDGE);
        virtio_status_or(VIRTIO_STATUS_DRIVER);
        (void)inl((uint16_t)(g_io_base + VIRTIO_PCI_HOST_FEATURES));
        outl((uint16_t)(g_io_base + VIRTIO_PCI_GUEST_FEATURES), 0u);
    }

    if (!virtio_setup_queue(&g_control_queue, VIRTIO_GPU_QUEUE_CONTROL, 2u)) {
        console_write("virtio-gpu: queue setup failed\n");
        virtio_status_or(VIRTIO_STATUS_FAILED);
        return;
    }

    g_adaptive = true;
    virtio_status_or(VIRTIO_STATUS_DRIVER_OK);

    uint32_t width = 0u;
    uint32_t height = 0u;
    if (!query_display_size(&width, &height) || !apply_resize(width, height)) {
        console_write("virtio-gpu: adaptive framebuffer setup failed\n");
        g_adaptive = false;
        virtio_status_or(VIRTIO_STATUS_FAILED);
        return;
    }

    console_printf("virtio-gpu: %s adaptive framebuffer %ux%u\n", g_modern ? "modern" : "legacy", (unsigned)g_width,
                   (unsigned)g_height);
}

void virtio_gpu_poll(void) {
    if (!g_adaptive) {
        return;
    }

    uint8_t isr = g_modern ? g_isr_cfg[0] : inb((uint16_t)(g_io_base + VIRTIO_PCI_ISR));
    uint32_t events = virtio_gpu_config_read32(0u);
    bool display_event = (events & VIRTIO_GPU_EVENT_DISPLAY) != 0u;
    if (display_event) {
        virtio_gpu_config_write32(4u, VIRTIO_GPU_EVENT_DISPLAY);
    }

    ++g_poll_counter;
    if (!display_event && (isr & 0x2u) == 0u && (g_poll_counter & 0x3fu) != 0u) {
        return;
    }
    uint32_t width = 0u;
    uint32_t height = 0u;
    if (!query_display_size(&width, &height)) {
        return;
    }
    stage_resize(width, height);
}

bool virtio_gpu_present(void) {
    return g_present;
}
