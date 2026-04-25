#include "virtio_gpu.h"

#include <stdbool.h>
#include <stdint.h>

#include "console.h"
#include "pci.h"

#define VIRTIO_VENDOR_ID 0x1AF4u
#define VIRTIO_GPU_MODERN_DEVICE_ID 0x1050u
#define VIRTIO_GPU_TRANSITIONAL_DEVICE_ID 0x1010u

static bool g_present;

void virtio_gpu_init(void) {
    struct pci_device dev;
    if (g_present) {
        return;
    }

    if (!pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_GPU_MODERN_DEVICE_ID, &dev) &&
        !pci_find_device(VIRTIO_VENDOR_ID, VIRTIO_GPU_TRANSITIONAL_DEVICE_ID, &dev)) {
        return;
    }

    uint16_t command = pci_read_config16(&dev, 4u);
    command |= 0x6u;
    pci_write_config16(&dev, 4u, command);

    g_present = true;
    console_write("virtio-gpu: controller present\n");
}

bool virtio_gpu_present(void) {
    return g_present;
}
