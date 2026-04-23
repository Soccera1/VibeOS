#include "power.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "console.h"
#include "fs.h"
#include "io.h"
#include "multiboot2.h"
#include "string.h"

#define ACPI_SIG_RSDP "RSD PTR "
#define ACPI_SIG_RSDT "RSDT"
#define ACPI_SIG_XSDT "XSDT"
#define ACPI_SIG_FADT "FACP"
#define ACPI_SIG_DSDT "DSDT"

#define ACPI_ADDRESS_SPACE_SYSTEM_IO 1u

#define ACPI_PM1_CNT_SCI_EN 0x0001u
#define ACPI_PM1_CNT_SLP_TYP_MASK 0x1C00u
#define ACPI_PM1_CNT_SLP_EN 0x2000u

#define ACPI_NAME_OP 0x08u
#define ACPI_ROOT_PREFIX 0x5Cu
#define ACPI_PACKAGE_OP 0x12u
#define ACPI_ZERO_OP 0x00u
#define ACPI_ONE_OP 0x01u
#define ACPI_BYTE_PREFIX 0x0Au
#define ACPI_WORD_PREFIX 0x0Bu
#define ACPI_DWORD_PREFIX 0x0Cu
#define ACPI_QWORD_PREFIX 0x0Eu

struct acpi_table_header {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    char asl_compiler_id[4];
    uint32_t asl_compiler_revision;
} __attribute__((packed));

struct acpi_rsdp {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_physical_address;
    uint32_t length;
    uint64_t xsdt_physical_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed));

struct acpi_generic_address {
    uint8_t space_id;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t access_width;
    uint64_t address;
} __attribute__((packed));

struct acpi_table_fadt {
    struct acpi_table_header header;
    uint32_t facs;
    uint32_t dsdt;
    uint8_t model;
    uint8_t preferred_profile;
    uint16_t sci_interrupt;
    uint32_t smi_command;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4_bios_request;
    uint8_t pstate_control;
    uint32_t pm1a_event_block;
    uint32_t pm1b_event_block;
    uint32_t pm1a_control_block;
    uint32_t pm1b_control_block;
    uint32_t pm2_control_block;
    uint32_t pm_timer_block;
    uint32_t gpe0_block;
    uint32_t gpe1_block;
    uint8_t pm1_event_length;
    uint8_t pm1_control_length;
    uint8_t pm2_control_length;
    uint8_t pm_timer_length;
    uint8_t gpe0_block_length;
    uint8_t gpe1_block_length;
    uint8_t gpe1_base;
    uint8_t cst_control;
    uint16_t c2_latency;
    uint16_t c3_latency;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alarm;
    uint8_t month_alarm;
    uint8_t century;
    uint16_t boot_flags;
    uint8_t reserved;
    uint32_t flags;
    struct acpi_generic_address reset_register;
    uint8_t reset_value;
    uint16_t arm_boot_flags;
    uint8_t minor_revision;
    uint64_t xfacs;
    uint64_t xdsdt;
    struct acpi_generic_address xpm1a_event_block;
    struct acpi_generic_address xpm1b_event_block;
    struct acpi_generic_address xpm1a_control_block;
    struct acpi_generic_address xpm1b_control_block;
    struct acpi_generic_address xpm2_control_block;
    struct acpi_generic_address xpm_timer_block;
    struct acpi_generic_address xgpe0_block;
    struct acpi_generic_address xgpe1_block;
    struct acpi_generic_address sleep_control;
    struct acpi_generic_address sleep_status;
    uint64_t hypervisor_id;
} __attribute__((packed));

struct acpi_power_state {
    bool ready;
    bool s5_valid;
    uint16_t pm1a_control;
    uint16_t pm1b_control;
    uint16_t slp_typa;
    uint16_t slp_typb;
    uint16_t smi_command;
    uint8_t acpi_enable;
};

static struct acpi_power_state g_acpi_power;
static bool g_fs_shutdown_done;

static void shutdown_filesystems_once(void) {
    if (g_fs_shutdown_done) {
        return;
    }
    g_fs_shutdown_done = true;
    (void)fs_shutdown();
}

static void wait_for_kbc(void) {
    for (uint32_t spins = 0; spins < 0x10000u; ++spins) {
        if ((inb(0x64) & 0x02u) == 0u) {
            return;
        }
        io_wait();
    }
}

static void halt_forever(void) __attribute__((noreturn));

static void halt_forever(void) {
    cli();
    for (;;) {
        hlt();
    }
}

static bool phys_range_valid(uint64_t phys, size_t len) {
    if (len == 0) {
        return false;
    }
    if (phys >= (1ull << 30)) {
        return false;
    }
    if (phys + (uint64_t)len < phys) {
        return false;
    }
    return phys + (uint64_t)len <= (1ull << 30);
}

static const void* phys_ptr(uint64_t phys, size_t len) {
    if (!phys_range_valid(phys, len)) {
        return 0;
    }
    return (const void*)(uintptr_t)phys;
}

static bool checksum_ok(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint8_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum = (uint8_t)(sum + bytes[i]);
    }
    return sum == 0;
}

static const struct acpi_table_header* table_from_phys(uint64_t phys, const char* sig) {
    const struct acpi_table_header* header = (const struct acpi_table_header*)phys_ptr(phys, sizeof(*header));
    if (header == 0) {
        return 0;
    }
    if (sig != 0 && memcmp(header->signature, sig, 4) != 0) {
        return 0;
    }
    const struct acpi_table_header* full = (const struct acpi_table_header*)phys_ptr(phys, header->length);
    if (full == 0 || header->length < sizeof(*header) || !checksum_ok(full, header->length)) {
        return 0;
    }
    return full;
}

static bool aml_parse_package_length(const uint8_t* aml, size_t len, size_t* consumed, uint32_t* value) {
    if (len == 0) {
        return false;
    }

    uint8_t lead = aml[0];
    size_t follow = (size_t)(lead >> 6);
    if (len < 1 + follow) {
        return false;
    }

    uint32_t out = (uint32_t)(lead & 0x0Fu);
    for (size_t i = 0; i < follow; ++i) {
        out |= ((uint32_t)aml[1 + i]) << (4 + (i * 8));
    }

    *consumed = 1 + follow;
    *value = out;
    return true;
}

static bool aml_parse_integer(const uint8_t* aml, size_t len, uint8_t* value, size_t* consumed) {
    if (len == 0) {
        return false;
    }

    switch (aml[0]) {
        case ACPI_ZERO_OP:
            *value = 0;
            *consumed = 1;
            return true;
        case ACPI_ONE_OP:
            *value = 1;
            *consumed = 1;
            return true;
        case ACPI_BYTE_PREFIX:
            if (len < 2) {
                return false;
            }
            *value = aml[1];
            *consumed = 2;
            return true;
        case ACPI_WORD_PREFIX:
            if (len < 3) {
                return false;
            }
            *value = aml[1];
            *consumed = 3;
            return true;
        case ACPI_DWORD_PREFIX:
            if (len < 5) {
                return false;
            }
            *value = aml[1];
            *consumed = 5;
            return true;
        case ACPI_QWORD_PREFIX:
            if (len < 9) {
                return false;
            }
            *value = aml[1];
            *consumed = 9;
            return true;
        default:
            if (aml[0] <= 0x3Fu) {
                *value = aml[0];
                *consumed = 1;
                return true;
            }
            return false;
    }
}

static bool dsdt_extract_s5(const struct acpi_table_header* dsdt, uint16_t* slp_typa, uint16_t* slp_typb) {
    const uint8_t* aml = (const uint8_t*)dsdt + sizeof(*dsdt);
    size_t len = dsdt->length - sizeof(*dsdt);

    for (size_t i = 0; i + 4 < len; ++i) {
        if (memcmp(&aml[i], "_S5_", 4) != 0) {
            continue;
        }

        bool named = false;
        if (i >= 1 && aml[i - 1] == ACPI_NAME_OP) {
            named = true;
        }
        if (i >= 2 && aml[i - 2] == ACPI_NAME_OP && aml[i - 1] == ACPI_ROOT_PREFIX) {
            named = true;
        }
        if (!named) {
            continue;
        }

        const uint8_t* p = &aml[i + 4];
        size_t remain = len - (i + 4);
        if (remain == 0 || p[0] != ACPI_PACKAGE_OP) {
            continue;
        }

        ++p;
        --remain;

        size_t pkg_len_bytes = 0;
        uint32_t pkg_len = 0;
        if (!aml_parse_package_length(p, remain, &pkg_len_bytes, &pkg_len)) {
            continue;
        }
        p += pkg_len_bytes;
        remain -= pkg_len_bytes;
        if (remain == 0 || remain < pkg_len) {
            continue;
        }

        uint8_t elements = p[0];
        ++p;
        --remain;

        size_t used = 0;
        uint8_t val_a = 0;
        uint8_t val_b = 0;
        if (!aml_parse_integer(p, remain, &val_a, &used)) {
            continue;
        }
        p += used;
        remain -= used;

        if (elements >= 2) {
            if (!aml_parse_integer(p, remain, &val_b, &used)) {
                continue;
            }
        }

        *slp_typa = (uint16_t)val_a << 10;
        *slp_typb = (uint16_t)val_b << 10;
        return true;
    }

    return false;
}

static uint16_t gas_io_port(const struct acpi_generic_address* gas) {
    if (gas->space_id != ACPI_ADDRESS_SPACE_SYSTEM_IO || gas->address == 0 || gas->address > 0xFFFFu) {
        return 0;
    }
    return (uint16_t)gas->address;
}

static const struct acpi_table_fadt* find_fadt(const struct acpi_rsdp* rsdp) {
    if (rsdp->revision >= 2 && rsdp->xsdt_physical_address != 0) {
        const struct acpi_table_header* xsdt = table_from_phys(rsdp->xsdt_physical_address, ACPI_SIG_XSDT);
        if (xsdt != 0) {
            size_t entries = (xsdt->length - sizeof(*xsdt)) / sizeof(uint64_t);
            const uint64_t* table_entries = (const uint64_t*)((const uint8_t*)xsdt + sizeof(*xsdt));
            for (size_t i = 0; i < entries; ++i) {
                const struct acpi_table_header* table = table_from_phys(table_entries[i], 0);
                if (table != 0 && memcmp(table->signature, ACPI_SIG_FADT, 4) == 0) {
                    return (const struct acpi_table_fadt*)table;
                }
            }
        }
    }

    if (rsdp->rsdt_physical_address != 0) {
        const struct acpi_table_header* rsdt = table_from_phys(rsdp->rsdt_physical_address, ACPI_SIG_RSDT);
        if (rsdt != 0) {
            size_t entries = (rsdt->length - sizeof(*rsdt)) / sizeof(uint32_t);
            const uint32_t* table_entries = (const uint32_t*)((const uint8_t*)rsdt + sizeof(*rsdt));
            for (size_t i = 0; i < entries; ++i) {
                const struct acpi_table_header* table = table_from_phys(table_entries[i], 0);
                if (table != 0 && memcmp(table->signature, ACPI_SIG_FADT, 4) == 0) {
                    return (const struct acpi_table_fadt*)table;
                }
            }
        }
    }

    return 0;
}

static bool acpi_parse_power_state(const struct acpi_rsdp* rsdp) {
    const struct acpi_table_fadt* fadt = find_fadt(rsdp);
    if (fadt == 0 || fadt->header.length < offsetof(struct acpi_table_fadt, xpm1b_control_block) + sizeof(fadt->xpm1b_control_block)) {
        return false;
    }

    uint64_t dsdt_phys = fadt->xdsdt != 0 ? fadt->xdsdt : (uint64_t)fadt->dsdt;
    const struct acpi_table_header* dsdt = table_from_phys(dsdt_phys, ACPI_SIG_DSDT);
    if (dsdt == 0) {
        return false;
    }

    uint16_t pm1a_control = gas_io_port(&fadt->xpm1a_control_block);
    uint16_t pm1b_control = gas_io_port(&fadt->xpm1b_control_block);
    if (pm1a_control == 0 && fadt->pm1a_control_block <= 0xFFFFu) {
        pm1a_control = (uint16_t)fadt->pm1a_control_block;
    }
    if (pm1b_control == 0 && fadt->pm1b_control_block <= 0xFFFFu) {
        pm1b_control = (uint16_t)fadt->pm1b_control_block;
    }
    if (pm1a_control == 0) {
        return false;
    }

    uint16_t slp_typa = 0;
    uint16_t slp_typb = 0;
    if (!dsdt_extract_s5(dsdt, &slp_typa, &slp_typb)) {
        return false;
    }

    memset(&g_acpi_power, 0, sizeof(g_acpi_power));
    g_acpi_power.ready = true;
    g_acpi_power.s5_valid = true;
    g_acpi_power.pm1a_control = pm1a_control;
    g_acpi_power.pm1b_control = pm1b_control;
    g_acpi_power.slp_typa = slp_typa;
    g_acpi_power.slp_typb = slp_typb;
    if (fadt->smi_command <= 0xFFFFu) {
        g_acpi_power.smi_command = (uint16_t)fadt->smi_command;
    }
    g_acpi_power.acpi_enable = fadt->acpi_enable;
    return true;
}

void power_init(uint64_t mb2_info) {
    memset(&g_acpi_power, 0, sizeof(g_acpi_power));

    size_t rsdp_len = 0;
    const struct acpi_rsdp* rsdp = (const struct acpi_rsdp*)mb2_find_rsdp(mb2_info, &rsdp_len);
    if (rsdp == 0 || rsdp_len < 20 || memcmp(rsdp->signature, ACPI_SIG_RSDP, 8) != 0 || !checksum_ok(rsdp, 20)) {
        console_write("ACPI: RSDP unavailable\n");
        return;
    }
    if (rsdp->revision >= 2) {
        if (rsdp_len < sizeof(*rsdp) || rsdp->length < sizeof(*rsdp) || !checksum_ok(rsdp, rsdp->length)) {
            console_write("ACPI: RSDP invalid\n");
            return;
        }
    }

    if (!acpi_parse_power_state(rsdp)) {
        console_write("ACPI: S5 poweroff unavailable\n");
        return;
    }

    console_printf("ACPI: S5 via PM1a=%x PM1b=%x\n", (uint64_t)g_acpi_power.pm1a_control, (uint64_t)g_acpi_power.pm1b_control);
}

static void acpi_enable_if_needed(void) {
    if (!g_acpi_power.ready || g_acpi_power.smi_command == 0 || g_acpi_power.acpi_enable == 0) {
        return;
    }
    if ((inw(g_acpi_power.pm1a_control) & ACPI_PM1_CNT_SCI_EN) != 0u) {
        return;
    }

    outb(g_acpi_power.smi_command, g_acpi_power.acpi_enable);
    for (uint32_t spins = 0; spins < 0x200000u; ++spins) {
        if ((inw(g_acpi_power.pm1a_control) & ACPI_PM1_CNT_SCI_EN) != 0u) {
            return;
        }
        io_wait();
    }
}

static void acpi_power_off(void) {
    acpi_enable_if_needed();

    uint16_t pm1a = (uint16_t)(inw(g_acpi_power.pm1a_control) & ~(ACPI_PM1_CNT_SLP_TYP_MASK | ACPI_PM1_CNT_SLP_EN));
    uint16_t pm1b = 0;
    if (g_acpi_power.pm1b_control != 0) {
        pm1b = (uint16_t)(inw(g_acpi_power.pm1b_control) & ~(ACPI_PM1_CNT_SLP_TYP_MASK | ACPI_PM1_CNT_SLP_EN));
    }

    outw(g_acpi_power.pm1a_control, (uint16_t)(pm1a | g_acpi_power.slp_typa));
    if (g_acpi_power.pm1b_control != 0) {
        outw(g_acpi_power.pm1b_control, (uint16_t)(pm1b | g_acpi_power.slp_typb));
    }

    outw(g_acpi_power.pm1a_control, (uint16_t)(pm1a | g_acpi_power.slp_typa | ACPI_PM1_CNT_SLP_EN));
    if (g_acpi_power.pm1b_control != 0) {
        outw(g_acpi_power.pm1b_control, (uint16_t)(pm1b | g_acpi_power.slp_typb | ACPI_PM1_CNT_SLP_EN));
    }
}

void power_shutdown(void) {
    shutdown_filesystems_once();
    console_write("\nPowering off...\n");

    if (g_acpi_power.ready && g_acpi_power.s5_valid) {
        acpi_power_off();
        console_write("ACPI poweroff did not complete, falling back.\n");
    }

    outw(0x604, 0x2000);
    outw(0xB004, 0x2000);
    outw(0x4004, 0x3400);
    outb(0xF4, 0x00);
    halt_forever();
}

void power_halt(void) {
    shutdown_filesystems_once();
    console_write("\nSystem halted.\n");
    halt_forever();
}

void power_reboot(void) {
    shutdown_filesystems_once();
    console_write("\nRebooting...\n");
    wait_for_kbc();
    outb(0x64, 0xFE);
    halt_forever();
}
