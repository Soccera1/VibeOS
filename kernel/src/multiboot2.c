#include "multiboot2.h"

const struct mb2_tag_module* mb2_find_first_module(uint64_t mb2_info) {
    if (mb2_info == 0) {
        return 0;
    }

    const uint8_t* ptr = (const uint8_t*)(uintptr_t)(mb2_info + 8);
    for (;;) {
        const struct mb2_tag* tag = (const struct mb2_tag*)ptr;
        if (tag->type == MB2_TAG_END) {
            return 0;
        }
        if (tag->type == MB2_TAG_MODULE) {
            return (const struct mb2_tag_module*)tag;
        }
        ptr += (tag->size + 7u) & ~7u;
    }
}
