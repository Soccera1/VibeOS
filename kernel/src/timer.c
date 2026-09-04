#include "timer.h"

#include "console.h"
#include "io.h"

#define PIT_HZ 1193182ull
#define CALIBRATION_COUNT 59659u

_Static_assert(CONFIG_KERNEL_TIMER_HZ >= 19 && CONFIG_KERNEL_TIMER_HZ <= 1000,
               "CONFIG_KERNEL_TIMER_HZ must be between 19 and 1000 Hz");

static uint64_t cycles_per_usec;
static uint64_t boot_tsc;

void timer_init(void) {
    /* Channel 2 gives a reference interval even while interrupts are disabled.
     * Keep the speaker disabled and restore its gate after calibration. */
    uint8_t speaker = inb(0x61);
    outb(0x61, speaker & ~3u);
    outb(0x43, 0xB0); /* channel 2, low/high bytes, one-shot mode 0 */
    outb(0x42, CALIBRATION_COUNT & 0xffu);
    outb(0x42, CALIBRATION_COUNT >> 8);
    uint64_t start = read_tsc();
    outb(0x61, (speaker & ~2u) | 1u);
    unsigned attempts = 10000000;
    while ((inb(0x61) & 0x20u) == 0 && --attempts != 0) {
        __asm__ volatile("pause");
    }
    uint64_t elapsed = read_tsc() - start;
    outb(0x61, speaker);
    cycles_per_usec = elapsed * PIT_HZ / ((uint64_t)CALIBRATION_COUNT * 1000000ull);
    if (attempts == 0 || cycles_per_usec == 0) {
        console_write("PIT clock calibration failed\n");
        for (;;) hlt();
    }
    boot_tsc = read_tsc();

    /* Remap the legacy PIC away from exceptions; only IRQ0 is enabled.
     * Other devices continue to use their existing polling paths. */
    outb(0x20, 0x11); io_wait();
    outb(0xA0, 0x11); io_wait();
    outb(0x21, 0x20); io_wait();
    outb(0xA1, 0x28); io_wait();
    outb(0x21, 0x04); io_wait();
    outb(0xA1, 0x02); io_wait();
    outb(0x21, 0x01); io_wait();
    outb(0xA1, 0x01); io_wait();
    outb(0x21, 0xFE);
    outb(0xA1, 0xFF);

    uint16_t divisor = (uint16_t)(PIT_HZ / CONFIG_KERNEL_TIMER_HZ);
    outb(0x43, 0x34); /* channel 0, rate generator */
    outb(0x40, divisor & 0xffu);
    outb(0x40, divisor >> 8);
    console_printf("Timer: %u Hz, calibrated TSC %u cycles/us\n",
                   (unsigned)CONFIG_KERNEL_TIMER_HZ, cycles_per_usec);
}

uint64_t timer_cycles_per_usec(void) {
    return cycles_per_usec;
}

uint64_t timer_monotonic_ns(void) {
    return ((read_tsc() - boot_tsc) / cycles_per_usec) * 1000ull;
}
