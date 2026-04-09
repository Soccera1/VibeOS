#pragma once

#include <stddef.h>
#include <stdint.h>

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define LINUX_REBOOT_CMD1_CAD_OFF 0
#define LINUX_REBOOT_CMD_RESTART 0x01234567
#define LINUX_REBOOT_CMD_RESTART2 0xA1B2C3D4
#define LINUX_REBOOT_CMD_HALT 0xCDEF0123
#define LINUX_REBOOT_CMD_POWER_OFF 0x4321FEDC
