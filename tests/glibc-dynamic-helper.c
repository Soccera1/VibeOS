#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

static int constructor_ran;

__attribute__((constructor)) static void dynamic_constructor(void) {
    constructor_ran = 1;
}

int main(int argc, char** argv) {
    const char* marker = getenv("GLIBC_DYNAMIC_TEST");
    const char* allow_zero_base = getenv("GLIBC_DYNAMIC_ALLOW_ZERO_BASE");
    char* memory = malloc(32);
    volatile double input = 0.0;
    void* libm = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    double (*dynamic_cos)(double) = libm == NULL ? NULL : (double (*)(double))dlsym(libm, "cos");

    unsigned long phdr = getauxval(AT_PHDR);
    unsigned long base = getauxval(AT_BASE);
    double direct_result = cos(input);
    double dynamic_result = dynamic_cos == NULL ? -1.0 : dynamic_cos(input);
    if (memory == NULL || marker == NULL || strcmp(marker, "present") != 0 ||
        !constructor_ran || argc != 2 || strcmp(argv[1], "argument") != 0 ||
        phdr == 0 || (base == 0 && allow_zero_base == NULL) || direct_result != 1.0 || dynamic_result != 1.0) {
        fprintf(stderr,
                "glibc dynamic validation failed: memory=%d marker=%s constructor=%d argc=%d "
                "phdr=%lu base=%lu direct=%g dynamic=%g dlerror=%s\n",
                memory != NULL, marker == NULL ? "(null)" : marker, constructor_ran, argc,
                phdr, base, direct_result, dynamic_result, libm == NULL ? dlerror() : "none");
        free(memory);
        if (libm != NULL) {
            dlclose(libm);
        }
        return 1;
    }

    strcpy(memory, "allocation-ok");
    printf("glibc-dynamic-ok version=%s %s constructor=%d\n",
           gnu_get_libc_version(), memory, constructor_ran);
    free(memory);
    dlclose(libm);
    return 0;
}
