/* Baseline replacement for Gentoo's host-tuned libgcc __popcountdi2. */
__attribute__((visibility("hidden")))
unsigned int
__popcountdi2(unsigned long long value)
{
    value -= (value >> 1) & 0x5555555555555555ull;
    value = (value & 0x3333333333333333ull)
            + ((value >> 2) & 0x3333333333333333ull);
    value = (value + (value >> 4)) & 0x0f0f0f0f0f0f0f0full;
    value += value >> 8;
    value += value >> 16;
    value += value >> 32;
    return (unsigned int)(value & 0x7full);
}
