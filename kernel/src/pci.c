#include "pci.h"

#include <stddef.h>
#include <stdint.h>

#include "io.h"

#define PCI_CONFIG_ADDRESS 0xCF8u
#define PCI_CONFIG_DATA 0xCFCu

static uint32_t pci_address(uint8_t bus, uint8_t slot, uint8_t function, uint8_t offset) {
    return 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)slot << 11) | ((uint32_t)function << 8) |
           (uint32_t)(offset & 0xFCu);
}

uint32_t pci_read_config32(const struct pci_device* dev, uint8_t offset) {
    outl(PCI_CONFIG_ADDRESS, pci_address(dev->bus, dev->slot, dev->function, offset));
    return inl(PCI_CONFIG_DATA);
}

void pci_write_config32(const struct pci_device* dev, uint8_t offset, uint32_t value) {
    outl(PCI_CONFIG_ADDRESS, pci_address(dev->bus, dev->slot, dev->function, offset));
    outl(PCI_CONFIG_DATA, value);
}

uint16_t pci_read_config16(const struct pci_device* dev, uint8_t offset) {
    uint32_t value = pci_read_config32(dev, offset);
    return (uint16_t)(value >> ((offset & 2u) * 8u));
}

void pci_write_config16(const struct pci_device* dev, uint8_t offset, uint16_t value) {
    uint32_t old = pci_read_config32(dev, offset);
    uint32_t shift = (uint32_t)(offset & 2u) * 8u;
    old &= ~(0xFFFFu << shift);
    old |= (uint32_t)value << shift;
    pci_write_config32(dev, offset, old);
}

bool pci_find_device(uint16_t vendor_id, uint16_t device_id, struct pci_device* out) {
    for (uint16_t bus = 0; bus < 256u; ++bus) {
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t function = 0; function < 8u; ++function) {
                struct pci_device dev = {
                    .bus = (uint8_t)bus,
                    .slot = slot,
                    .function = function,
                };
                uint32_t id = pci_read_config32(&dev, 0u);
                if (id == 0xFFFFFFFFu) {
                    continue;
                }
                dev.vendor_id = (uint16_t)id;
                dev.device_id = (uint16_t)(id >> 16);
                if (dev.vendor_id == vendor_id && dev.device_id == device_id) {
                    if (out != NULL) {
                        *out = dev;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

uint16_t pci_io_bar(const struct pci_device* dev, uint8_t bar) {
    if (bar >= 6u) {
        return 0u;
    }
    uint32_t value = pci_read_config32(dev, (uint8_t)(0x10u + bar * 4u));
    if ((value & 1u) == 0u) {
        return 0u;
    }
    return (uint16_t)(value & ~3u);
}

uint32_t pci_mem_bar(const struct pci_device* dev, uint8_t bar) {
    if (bar >= 6u) {
        return 0u;
    }
    uint32_t value = pci_read_config32(dev, (uint8_t)(0x10u + bar * 4u));
    if ((value & 1u) != 0u) {
        return 0u;
    }
    uint32_t type = (value >> 1) & 0x3u;
    if (type == 0x2u && bar < 5u) {
        uint32_t high = pci_read_config32(dev, (uint8_t)(0x10u + (bar + 1u) * 4u));
        if (high != 0u) {
            return 0u;
        }
    } else if (type != 0u) {
        return 0u;
    }
    return value & ~0xFu;
}

bool pci_find_virtio_cap(const struct pci_device* dev, uint8_t cfg_type, struct pci_virtio_cap* out) {
    uint16_t status = pci_read_config16(dev, 0x06u);
    if ((status & 0x10u) == 0u) {
        return false;
    }

    uint8_t cap = (uint8_t)(pci_read_config32(dev, 0x34u) & 0xFCu);
    for (uint8_t limit = 0; cap != 0u && limit < 48u; ++limit) {
        uint32_t head = pci_read_config32(dev, cap);
        uint8_t cap_id = (uint8_t)(head & 0xFFu);
        uint8_t next = (uint8_t)((head >> 8) & 0xFCu);
        if (cap_id == 0x09u && ((head >> 24) & 0xFFu) == cfg_type) {
            if (out != NULL) {
                out->cfg_type = cfg_type;
                out->bar = (uint8_t)(pci_read_config32(dev, (uint8_t)(cap + 4u)) & 0xFFu);
                out->offset = pci_read_config32(dev, (uint8_t)(cap + 8u));
                out->length = pci_read_config32(dev, (uint8_t)(cap + 12u));
                out->notify_off_multiplier = 0u;
                if (cfg_type == 2u) {
                    out->notify_off_multiplier = pci_read_config32(dev, (uint8_t)(cap + 16u));
                }
            }
            return true;
        }
        cap = next;
    }
    return false;
}
