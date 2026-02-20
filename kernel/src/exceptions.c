#include <stdint.h>

#include "console.h"
#include "io.h"

struct exception_frame {
    uint64_t vector;
    uint64_t error;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

void exception_dispatch(struct exception_frame* frame) {
    console_printf("\nEXCEPTION vec=%u err=%x rip=%x cs=%x rflags=%x rsp=%x ss=%x cr2=%x\n", (unsigned)frame->vector,
                   (unsigned)frame->error, frame->rip, frame->cs, frame->rflags, frame->rsp, frame->ss, read_cr2());
}
