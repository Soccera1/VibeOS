#include "multiboot2.h"

#include "string.h"

static const struct mb2_tag* mb2_first_tag(uint64_t mb2_info) {
    if (mb2_info == 0) {
        return 0;
    }
    return (const struct mb2_tag*)(uintptr_t)(mb2_info + 8);
}

static const struct mb2_tag* mb2_next_tag(const struct mb2_tag* tag) {
    return (const struct mb2_tag*)((const uint8_t*)tag + ((tag->size + 7u) & ~7u));
}

const struct mb2_tag_module* mb2_find_module(uint64_t mb2_info, size_t index) {
    size_t current = 0;
    for (const struct mb2_tag* tag = mb2_first_tag(mb2_info); tag != 0; tag = mb2_next_tag(tag)) {
        if (tag->type == MB2_TAG_END) {
            return 0;
        }
        if (tag->type == MB2_TAG_MODULE && current++ == index) {
            return (const struct mb2_tag_module*)tag;
        }
    }
    return 0;
}

const void* mb2_find_rsdp(uint64_t mb2_info, size_t* rsdp_len) {
    const struct mb2_tag* best = 0;

    for (const struct mb2_tag* tag = mb2_first_tag(mb2_info); tag != 0; tag = mb2_next_tag(tag)) {
        if (tag->type == MB2_TAG_END) {
            break;
        }
        if (tag->type == MB2_TAG_ACPI_NEW) {
            best = tag;
            break;
        }
        if (tag->type == MB2_TAG_ACPI_OLD) {
            best = tag;
        }
    }

    if (best == 0 || best->size <= sizeof(*best)) {
        return 0;
    }

    if (rsdp_len != 0) {
        *rsdp_len = (size_t)(best->size - sizeof(*best));
    }
    return (const uint8_t*)best + sizeof(*best);
}

struct mb2_tag_framebuffer_common {
    uint32_t type;
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t framebuffer_bpp;
    uint8_t framebuffer_type;
    uint16_t reserved;
} __attribute__((packed));

struct mb2_tag_framebuffer_rgb {
    uint8_t red_field_position;
    uint8_t red_mask_size;
    uint8_t green_field_position;
    uint8_t green_mask_size;
    uint8_t blue_field_position;
    uint8_t blue_mask_size;
} __attribute__((packed));

bool mb2_find_framebuffer(uint64_t mb2_info, struct mb2_framebuffer_info* out) {
    if (out != 0) {
        memset(out, 0, sizeof(*out));
    }

    for (const struct mb2_tag* tag = mb2_first_tag(mb2_info); tag != 0; tag = mb2_next_tag(tag)) {
        if (tag->type == MB2_TAG_END) {
            break;
        }
        if (tag->type != MB2_TAG_FRAMEBUFFER || tag->size < sizeof(struct mb2_tag_framebuffer_common)) {
            continue;
        }

        const struct mb2_tag_framebuffer_common* fb = (const struct mb2_tag_framebuffer_common*)tag;
        if (fb->framebuffer_type != 1u ||
            tag->size < sizeof(struct mb2_tag_framebuffer_common) + sizeof(struct mb2_tag_framebuffer_rgb)) {
            return false;
        }

        if (out == 0) {
            return true;
        }

        const struct mb2_tag_framebuffer_rgb* rgb =
            (const struct mb2_tag_framebuffer_rgb*)((const uint8_t*)fb + sizeof(*fb));
        out->addr = fb->framebuffer_addr;
        out->pitch = fb->framebuffer_pitch;
        out->width = fb->framebuffer_width;
        out->height = fb->framebuffer_height;
        out->bpp = fb->framebuffer_bpp;
        out->type = fb->framebuffer_type;
        out->red_field_position = rgb->red_field_position;
        out->red_mask_size = rgb->red_mask_size;
        out->green_field_position = rgb->green_field_position;
        out->green_mask_size = rgb->green_mask_size;
        out->blue_field_position = rgb->blue_field_position;
        out->blue_mask_size = rgb->blue_mask_size;
        out->reserved_field_position = 0u;
        out->reserved_mask_size = 0u;
        return true;
    }

    return false;
}
