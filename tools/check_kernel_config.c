#define _GNU_SOURCE
#include "kconfig.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int run(char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (!pid) { execvp(argv[0],argv); perror(argv[0]); _exit(127); }
    int status;
    while (waitpid(pid,&status,0) < 0) if (errno != EINTR) { perror("waitpid"); return 1; }
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
static void set(Model* model, const char* name, const char* value) {
    int index = find_symbol(model,name);
    if (index < 0) { fprintf(stderr,"Missing symbol: %s\n",name); exit(1); }
    set_string(&model->symbols[index].value,value);
}
static int expect(Model* model, const char* name, const char* value) {
    int i = find_symbol(model,name);
    if (i >= 0 && !strcmp(model->symbols[i].value,value)) return 0;
    fprintf(stderr,"Unexpected CONFIG_%s (expected %s)\n",name,value); return 1;
}
int main(void) {
    const char* variants[] = {"default","disabled","mixed","no-keyboard","no-evdev"};
    const char* tests[] = {"kernel-config","kernel-input-config","kernel-fs-config"};
    char temporary[] = "/tmp/vibeos-config-XXXXXX";
    if (!mkdtemp(temporary)) { perror("mkdtemp"); return 1; }
    char config[256], mk[256], header[256], binary[256];
    snprintf(config,sizeof(config),"%s/.config",temporary);
    snprintf(mk,sizeof(mk),"%s/config.mk",temporary);
    snprintf(header,sizeof(header),"%s/autoconf.h",temporary);
    snprintf(binary,sizeof(binary),"%s/test",temporary);
    int result = 0;
    for (size_t v = 0; v < 5 && !result; ++v) {
        Model model = parse_kconfig("Kconfig");
        if (v == 1) {
            for (size_t i = 0; i < model.count; ++i)
                if (!strncmp(model.symbols[i].name,"KERNEL_",7) && !strcmp(model.symbols[i].type,"bool"))
                    set_string(&model.symbols[i].value,"n");
        } else if (v == 2) {
            set(&model,"KERNEL_INET","n"); set(&model,"KERNEL_EXT2","n");
            set(&model,"KERNEL_PS2_MOUSE","n"); set(&model,"KERNEL_PTYS","n");
        } else if (v == 3) set(&model,"KERNEL_PS2_KEYBOARD","n");
        else if (v == 4) set(&model,"KERNEL_INPUT_EVENTS","n");
        resolve(&model);
        if (v == 2) {
            const char* disabled[] = {"KERNEL_VIRTIO_NET","KERNEL_TCP_SOCKETS","KERNEL_UDP_SOCKETS",
                "KERNEL_RAW_ICMP_SOCKETS","KERNEL_ICMP_ECHO","KERNEL_EXT2_WRITE"};
            for (size_t i = 0; i < 6; ++i) result |= expect(&model,disabled[i],"n");
            result |= expect(&model,"KERNEL_USR_AUTOMOUNT","y");
            result |= expect(&model,"KERNEL_HOME_AUTOMOUNT","y");
        }
        if (v == 1 || v == 2 || v == 3)
            result |= expect(&model,"KERNEL_INPUT_EVENTS",v == 1 ? "n" : "y");
        result |= write_config(&model,config) != 0;
        result |= write_outputs(&model,mk,header) != 0;
        Model loaded = parse_kconfig("Kconfig"); parse_config(&loaded,config); resolve(&loaded);
        for (size_t i = 0; i < model.count; ++i)
            result |= strcmp(model.symbols[i].value,loaded.symbols[i].value) != 0;
        free_model(&loaded); free_model(&model);
        printf("%s:\n",variants[v]); fflush(stdout);
        for (size_t t = 0; t < 3 && !result; ++t) {
            char source[256]; snprintf(source,sizeof(source),"tests/%s-host-test.c",tests[t]);
            char* cc[] = {"tools/musl_toolchain.sh","cc","-static","-no-pie","-std=gnu11","-O2",
                "-fno-builtin","-ffunction-sections","-fdata-sections","-Wall","-Wextra","-Werror",
                "-Ikernel/include","-include",header,"-Wl,--gc-sections",source,"-o",binary,NULL};
            result = run(cc);
            if (!result) { char* execute[] = {binary,NULL}; result = run(execute); }
        }
    }
    unlink(config); unlink(mk); unlink(header); unlink(binary); rmdir(temporary);
    return result ? 1 : 0;
}
