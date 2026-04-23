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
