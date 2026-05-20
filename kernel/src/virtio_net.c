#include "virtio_net.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "io.h"
#include "kmalloc.h"
#include "net.h"
#include "pci.h"
#include "string.h"

#define VIRTIO_VENDOR_ID 0x1AF4u
#define VIRTIO_NET_DEVICE_ID 0x1000u

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
#define VIRTIO_STATUS_FAILED 128u

#define VIRTIO_NET_F_MAC 5u
#define VIRTIO_NET_QUEUE_RX 0u
#define VIRTIO_NET_QUEUE_TX 1u
#define VIRTIO_NET_RX_BUFFERS 32u
#define VIRTIO_NET_TX_BUFFERS 32u
#define VIRTIO_NET_FRAME_CAPACITY 2048u
#define VIRTIO_NET_TX_SPIN_LIMIT 200000u

#define VRING_DESC_F_NEXT 1u
#define VRING_DESC_F_WRITE 2u
#define VRING_ALIGN 4096u

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

struct virtio_net_hdr {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __attribute__((packed));

struct virtio_net_queue {
    void* raw;
    uint16_t size;
    uint16_t next_desc;
    struct vring_desc* desc;
    volatile struct vring_avail* avail;
    volatile struct vring_used* used;
    uint16_t last_used_idx;
};

struct rx_buffer {
    struct virtio_net_hdr hdr;
    uint8_t frame[VIRTIO_NET_FRAME_CAPACITY];
} __attribute__((aligned(16)));

struct tx_buffer {
    struct virtio_net_hdr hdr;
    uint8_t frame[VIRTIO_NET_FRAME_CAPACITY];
} __attribute__((aligned(16)));

static struct virtio_net_queue g_rx_queue;
static struct virtio_net_queue g_tx_queue;
static struct rx_buffer g_rx_buffers[VIRTIO_NET_RX_BUFFERS];
static struct tx_buffer g_tx_buffers[VIRTIO_NET_TX_BUFFERS];
static uint16_t g_io_base;
static uint8_t g_mac[NET_ETH_ADDR_LEN];
static bool g_present;

static char hex_digit(uint8_t value) {
    value &= 0x0Fu;
    if (value < 10u) {
        return (char)('0' + (int)value);
    }
    return (char)('a' + (int)(value - 10u));
}

static void format_mac(const uint8_t mac[NET_ETH_ADDR_LEN], char out[18]) {
    size_t pos = 0;
    for (size_t i = 0; i < NET_ETH_ADDR_LEN; ++i) {
        out[pos++] = hex_digit((uint8_t)(mac[i] >> 4));
        out[pos++] = hex_digit(mac[i]);
        if (i + 1u != NET_ETH_ADDR_LEN) {
            out[pos++] = ':';
        }
    }
    out[pos] = '\0';
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
    outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), (uint8_t)(inb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS)) | value));
}

static bool virtio_setup_queue(struct virtio_net_queue* queue, uint16_t queue_index, uint16_t min_size) {
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

static void virtio_net_submit_rx(uint16_t desc_id) {
    if (desc_id >= VIRTIO_NET_RX_BUFFERS || desc_id >= g_rx_queue.size) {
        return;
    }

    memset(&g_rx_buffers[desc_id], 0, sizeof(g_rx_buffers[desc_id]));
    g_rx_queue.desc[desc_id].addr = (uint64_t)(uintptr_t)&g_rx_buffers[desc_id];
    g_rx_queue.desc[desc_id].len = sizeof(g_rx_buffers[desc_id]);
    g_rx_queue.desc[desc_id].flags = VRING_DESC_F_WRITE;
    g_rx_queue.desc[desc_id].next = 0u;
    __asm__ volatile("mfence" : : : "memory");
    g_rx_queue.avail->ring[g_rx_queue.avail->idx % g_rx_queue.size] = desc_id;
    __asm__ volatile("mfence" : : : "memory");
    ++g_rx_queue.avail->idx;
    __asm__ volatile("mfence" : : : "memory");
}

static void virtio_net_notify_queue(uint16_t queue_index) {
    outw((uint16_t)(g_io_base + VIRTIO_PCI_QUEUE_NOTIFY), queue_index);
}

static uint16_t virtio_net_alloc_tx_desc(void) {
    uint16_t desc = g_tx_queue.next_desc;
    ++g_tx_queue.next_desc;
    if (g_tx_queue.next_desc >= g_tx_queue.size || g_tx_queue.next_desc >= VIRTIO_NET_TX_BUFFERS) {
        g_tx_queue.next_desc = 0u;
    }
    return desc;
}

void virtio_net_poll(void) {
    if (!g_present) {
        return;
    }

    (void)inb((uint16_t)(g_io_base + VIRTIO_PCI_ISR));
    while (g_rx_queue.last_used_idx != g_rx_queue.used->idx) {
        struct vring_used_elem elem = g_rx_queue.used->ring[g_rx_queue.last_used_idx % g_rx_queue.size];
        ++g_rx_queue.last_used_idx;
        if (elem.id < VIRTIO_NET_RX_BUFFERS && elem.id < g_rx_queue.size) {
            if (elem.len > sizeof(struct virtio_net_hdr)) {
                size_t frame_len = elem.len - sizeof(struct virtio_net_hdr);
                if (frame_len > VIRTIO_NET_FRAME_CAPACITY) {
                    frame_len = VIRTIO_NET_FRAME_CAPACITY;
                }
                net_receive_ethernet(g_rx_buffers[elem.id].frame, frame_len);
            }
            virtio_net_submit_rx((uint16_t)elem.id);
            virtio_net_notify_queue(VIRTIO_NET_QUEUE_RX);
        }
    }
}

bool virtio_net_send(const void* frame, size_t len) {
    if (!g_present || frame == NULL || len == 0u || len > VIRTIO_NET_FRAME_CAPACITY || g_tx_queue.size < 2u) {
        return false;
    }

    virtio_net_poll();
    uint16_t desc = virtio_net_alloc_tx_desc();
    struct tx_buffer* tx = &g_tx_buffers[desc];
    memset(tx, 0, sizeof(*tx));
    memcpy(tx->frame, frame, len);
    g_tx_queue.desc[desc].addr = (uint64_t)(uintptr_t)tx;
    g_tx_queue.desc[desc].len = (uint32_t)(sizeof(struct virtio_net_hdr) + len);
    g_tx_queue.desc[desc].flags = 0u;
    g_tx_queue.desc[desc].next = 0u;
    __asm__ volatile("mfence" : : : "memory");
    g_tx_queue.avail->ring[g_tx_queue.avail->idx % g_tx_queue.size] = desc;
    __asm__ volatile("mfence" : : : "memory");
    ++g_tx_queue.avail->idx;
    __asm__ volatile("mfence" : : : "memory");
    virtio_net_notify_queue(VIRTIO_NET_QUEUE_TX);

    for (uint32_t spins = 0; spins < VIRTIO_NET_TX_SPIN_LIMIT; ++spins) {
        virtio_net_poll();
        if (g_tx_queue.last_used_idx != g_tx_queue.used->idx) {
            ++g_tx_queue.last_used_idx;
            return true;
        }
        __asm__ volatile("pause" : : : "memory");
    }
    console_write("virtio-net: transmit timed out; disabling driver\n");
    g_present = false;
    virtio_status_or(VIRTIO_STATUS_FAILED);
    return false;
}

void virtio_net_init(void) {
    if (g_present) {
        return;
    }

    struct pci_device dev;
    if (!pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_NET_DEVICE_ID, &dev)) {
        return;
    }
    g_io_base = pci_io_bar(&dev, 0u);
    if (g_io_base == 0u) {
        console_write("virtio-net: controller has no legacy I/O BAR\n");
        return;
    }

    uint16_t command = pci_read_config16(&dev, 4u);
    command |= 0x5u;
    pci_write_config16(&dev, 4u, command);

    outb((uint16_t)(g_io_base + VIRTIO_PCI_STATUS), 0u);
    virtio_status_or(VIRTIO_STATUS_ACKNOWLEDGE);
    virtio_status_or(VIRTIO_STATUS_DRIVER);
    uint32_t host_features = inl((uint16_t)(g_io_base + VIRTIO_PCI_HOST_FEATURES));
    uint32_t guest_features = (host_features & (1u << VIRTIO_NET_F_MAC));
    outl((uint16_t)(g_io_base + VIRTIO_PCI_GUEST_FEATURES), guest_features);

    if ((host_features & (1u << VIRTIO_NET_F_MAC)) != 0u) {
        for (size_t i = 0; i < NET_ETH_ADDR_LEN; ++i) {
            g_mac[i] = inb((uint16_t)(g_io_base + VIRTIO_PCI_CONFIG + i));
        }
    } else {
        g_mac[0] = 0x52u;
        g_mac[1] = 0x54u;
        g_mac[2] = 0x00u;
        g_mac[3] = 0x12u;
        g_mac[4] = 0x34u;
        g_mac[5] = 0x56u;
    }

    if (!virtio_setup_queue(&g_rx_queue, VIRTIO_NET_QUEUE_RX, VIRTIO_NET_RX_BUFFERS) ||
        !virtio_setup_queue(&g_tx_queue, VIRTIO_NET_QUEUE_TX, 2u)) {
        console_write("virtio-net: queue setup failed\n");
        virtio_status_or(VIRTIO_STATUS_FAILED);
        return;
    }

    for (uint16_t i = 0; i < VIRTIO_NET_RX_BUFFERS; ++i) {
        virtio_net_submit_rx(i);
    }
    virtio_net_notify_queue(VIRTIO_NET_QUEUE_RX);

    g_present = true;
    virtio_status_or(VIRTIO_STATUS_DRIVER_OK);
    net_init(g_mac, virtio_net_send);
    char mac_text[18];
    format_mac(g_mac, mac_text);
    console_printf("virtio-net: %s attached\n", mac_text);
}

bool virtio_net_present(void) {
    return g_present;
}
