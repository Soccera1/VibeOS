#include "scsi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(e)                                                                                                       \
    do {                                                                                                               \
        if (!(e)) {                                                                                                    \
            fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #e);                                            \
            exit(1);                                                                                                   \
        }                                                                                                              \
    } while (0)

static unsigned commands;
static int result;
static int command(void* ctx, const uint8_t* cdb, size_t len, void* data, size_t size, bool data_in) {
    CHECK(ctx == &commands);
    CHECK(len == 10 && cdb[0] == 0x35);
    for (size_t i = 1; i < len; ++i)
        CHECK(cdb[i] == 0);
    CHECK(data == NULL && size == 0 && !data_in);
    ++commands;
    return result;
}
int main(void) {
    const struct scsi_transport transport = {command};
    struct scsi_disk disk = {.present = true, .writable = true, .transport = &transport, .transport_ctx = &commands};
    const struct ext2_storage_ops* ops = scsi_disk_storage_ops();
    CHECK(ops->flush && ops->flush(&disk) == 0 && commands == 1);
    result = -1;
    CHECK(ops->flush(&disk) == -1 && commands == 2);
    disk.writable = false;
    CHECK(ops->flush(&disk) == -1 && commands == 2);
    disk.writable = true;
    disk.present = false;
    CHECK(ops->flush(&disk) == -1 && commands == 2);
    disk.present = true;
    disk.transport = NULL;
    CHECK(ops->flush(&disk) == -1 && commands == 2);
    const struct scsi_transport missing_command = {0};
    disk.transport = &missing_command;
    CHECK(ops->flush(&disk) == -1 && commands == 2);
    CHECK(ops->flush(NULL) == -1 && commands == 2);
    puts("SCSI flush checks passed");
    return 0;
}
