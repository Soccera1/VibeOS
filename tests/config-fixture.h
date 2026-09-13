#ifndef CONFIG_FIXTURE_H
#define CONFIG_FIXTURE_H
#include <assert.h>
#include <unistd.h>
static const char fixture[] =
    "mainmenu \"Test configuration\"\nmenu \"Options\"\n"
    "config PARENT\n bool \"Parent\"\n default y\n"
    "config CHILD\n bool \"Child\"\n default y\n depends on PARENT\n"
    "config NUMBER\n int \"Number\"\n default 42\n"
    "config ADDRESS\n hex \"Address\"\n default 0x10\n"
    "config TEXT\n string \"Text\"\n default \"hello\"\nendmenu\n";
static void test_setup(ConfigEditor* e, char* directory) {
    assert(mkdtemp(directory));
    assert(chdir(directory) == 0);
    FILE* f = fopen("Kconfig","w"); assert(f);
    assert(fputs(fixture,f) >= 0); assert(fclose(f) == 0);
    char name[] = "test";
    char* argv[] = {name,NULL};
    assert(editor_init(e,1,argv) == 0);
    assert(access(".config",F_OK) != 0);
}
static char* read_file(const char* path) {
    FILE* f = fopen(path,"r"); assert(f);
    assert(fseek(f,0,SEEK_END) == 0); long size = ftell(f); assert(size >= 0);
    rewind(f); char* data = (char*)malloc((size_t)size + 1); assert(data);
    assert(fread(data,1,(size_t)size,f) == (size_t)size); data[size] = 0; fclose(f);
    return data;
}
static void check_saved(ConfigEditor* e) {
    assert(!editor_dirty(e));
    Model m = parse_kconfig("Kconfig"); parse_config(&m,".config"); resolve(&m);
    assert(!strcmp(m.symbols[2].value,"123"));
    assert(!strcmp(m.symbols[3].value,"0xff"));
    assert(!strcmp(m.symbols[4].value,"quoted \"text\" \\ path"));
    free_model(&m);
    char* text = read_file("build/config.mk"); assert(strstr(text,"CONFIG_NUMBER := 123")); free(text);
    text = read_file("build/include/generated/autoconf.h");
    assert(strstr(text,"#define CONFIG_CHILD 1")); assert(strstr(text,"#define CONFIG_ADDRESS 0xff")); free(text);
}
static void test_cleanup(ConfigEditor* e, const char* directory) {
    editor_free(e);
    unlink("Kconfig"); unlink(".config"); unlink("build/config.mk"); unlink("build/include/generated/autoconf.h");
    rmdir("build/include/generated"); rmdir("build/include"); rmdir("build");
    assert(chdir("/") == 0); assert(rmdir(directory) == 0);
}
#endif
