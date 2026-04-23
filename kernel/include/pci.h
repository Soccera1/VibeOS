#pragma once

#include <stdbool.h>
#include <stdint.h>

struct pci_device {
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
};

bool pci_find_device(uint16_t vendor_id, uint16_t device_id, struct pci_device* out);
uint32_t pci_read_config32(const struct pci_device* dev, uint8_t offset);
void pci_write_config32(const struct pci_device* dev, uint8_t offset, uint32_t value);
uint16_t pci_read_config16(const struct pci_device* dev, uint8_t offset);
void pci_write_config16(const struct pci_device* dev, uint8_t offset, uint16_t value);
uint16_t pci_io_bar(const struct pci_device* dev, uint8_t bar);

