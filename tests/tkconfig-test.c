#define _GNU_SOURCE
#define CONFIG_GUI_TEST
#include "../tools/tkconfig.c"
#include "config-fixture.h"

static void run(Tcl_Interp* interp, const char* script) {
    int result = Tcl_Eval(interp,script);
    if (result != TCL_OK) fprintf(stderr,"Tcl test failed: %s\n",Tcl_GetStringResult(interp));
    assert(result == TCL_OK);
}
static void expect(Tcl_Interp* interp, const char* script, const char* value) {
    run(interp,script);
    assert(!strcmp(Tcl_GetStringResult(interp),value));
}
int main(int argc, char** argv) {
    (void)argc;
    Tcl_FindExecutable(argv[0]);
    Tcl_Interp* interp = Tcl_CreateInterp();
    assert(Tcl_Init(interp) == TCL_OK);
    if (Tk_Init(interp) != TCL_OK) {
        fprintf(stderr,"Tk tests require a display: %s\n",Tcl_GetStringResult(interp)); return 1;
    }
    ConfigEditor e;
    char directory[] = "/tmp/vibeos-tkconfig-test-XXXXXX";
    test_setup(&e,directory);
    set_string(&e.model.symbols[4].prompt,"Text [error injected]; $value {quoted}");
    assert(build_window(interp,&e) == TCL_OK);
    run(interp,"set backgroundErrors {}; proc bgerror {message} {lappend ::backgroundErrors $message}; update");
    expect(interp,"set backgroundErrors", "");
    expect(interp,".scroll.canvas.content.g0.r4.label cget -text","Text [error injected]; $value {quoted}");
    expect(interp,"config dirty","0");
    run(interp,"$widgets(0) invoke");
    assert(editor_dirty(&e));
    expect(interp,"$widgets(1) cget -state","disabled");
    expect(interp,"set values(1)","n");
    expect(interp,"save","1");
    run(interp,"$widgets(0) invoke");
    expect(interp,"$widgets(1) cget -state","normal");
    expect(interp,"set values(1)","y");
    /* Exercise textvariable traces, including replacement through the widget. */
    run(interp,"$widgets(2) delete 0 end; $widgets(2) insert 0 invalid");
    char* before = read_file(".config");
    run(interp,"rename tk_messageBox original_messageBox; set answer ok; set dialogs 0; proc tk_messageBox {args} {incr ::dialogs; return $::answer}");
    expect(interp,"save","0");
    expect(interp,"set dialogs","1");
    char* after = read_file(".config");
    assert(!strcmp(before,after)); free(before); free(after);
    run(interp,"set values(2) 123; set values(3) 0xff");
    Tcl_SetVar2(interp,"values","4","quoted \"text\" \\ path",TCL_GLOBAL_ONLY);
    expect(interp,"save","1"); check_saved(&e);
    run(interp,"set values(4) {[error injected]; $value {literal}}");
    assert(!strcmp(e.raw[4],"[error injected]; $value {literal}"));
    run(interp,"set closed 0; rename destroy original_destroy; proc destroy {window} {set ::closed 1}; set answer cancel; close");
    expect(interp,"set closed","0"); assert(editor_dirty(&e));
    run(interp,"set values(2) invalid; set answer yes; close");
    expect(interp,"set closed","0"); assert(editor_dirty(&e));
    run(interp,"set values(2) 123; close");
    expect(interp,"set closed","1"); assert(!editor_dirty(&e));
    /* Discard requests closure without touching the saved files. */
    run(interp,"set closed 0");
    before = read_file(".config");
    run(interp,"set values(4) discarded; set answer no; close");
    expect(interp,"set closed","1");
    after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
    run(interp,"original_destroy .");
    assert(Tk_GetNumMainWindows() == 0);
    Tcl_DeleteInterp(interp); Tcl_Finalize();
    test_cleanup(&e,directory);
    puts("Tk editor tests passed");
    return 0;
}
