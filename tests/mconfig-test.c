#define _GNU_SOURCE
#define CONFIG_GUI_TEST
#include "../tools/mconfig.c"
#include "config-fixture.h"
#include <sys/wait.h>

static void answer(ConfigWindow* w, const char* callback, int reason) {
    assert(w->close_dialog && XtIsManaged(w->close_dialog));
    XmAnyCallbackStruct event = { .reason = reason };
    XtCallCallbacks(w->close_dialog,callback,&event);
    assert(!w->close_dialog);
}
static void run_test(int argc, char** argv, bool discard) {
    XtToolkitInitialize();
    XtAppContext app = XtCreateApplicationContext();
    Display* display = XtOpenDisplay(app,NULL,"test","Mconfig",NULL,0,&argc,argv);
    assert(display);
    Widget shell = XtAppCreateShell("test","Mconfig",applicationShellWidgetClass,display,NULL,0);
    ConfigEditor e; char directory[] = "/tmp/vibeos-mconfig-test-XXXXXX"; test_setup(&e,directory);
    ConfigWindow w; build_window(&w,&e,app,shell); XtRealizeWidget(shell);
    while (XtAppPending(app)) XtAppProcessEvent(app,XtIMAll);
    XmToggleButtonSetState(w.widgets[0],False,True);
    assert(editor_dirty(&e) && !XtIsSensitive(w.widgets[1]));
    assert(!XmToggleButtonGetState(w.widgets[1]));
    assert(save(&w));
    XmToggleButtonSetState(w.widgets[0],True,True);
    assert(XtIsSensitive(w.widgets[1]) && XmToggleButtonGetState(w.widgets[1]));
    XmTextFieldSetString(w.widgets[2],"invalid");
    char* before = read_file(".config");
    assert(!save(&w) && w.error_dialog && XtIsManaged(w.error_dialog));
    XtCallCallbacks(w.error_dialog,XmNokCallback,NULL);
    assert(!w.error_dialog);
    char* after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
    /* Save on close must also keep the editor open on validation failure. */
    close_clicked(NULL,&w,NULL); answer(&w,XmNokCallback,XmCR_OK);
    assert(!XtAppGetExitFlag(app) && w.error_dialog);
    XtCallCallbacks(w.error_dialog,XmNokCallback,NULL);
    XmTextFieldSetString(w.widgets[2],"123");
    XmTextFieldSetString(w.widgets[3],"0xff");
    XmTextFieldSetString(w.widgets[4],"quoted \"text\" \\ path");
    save_clicked(NULL,&w,NULL); check_saved(&e);
    before = read_file(".config");
    XmTextFieldSetString(w.widgets[4],"unsaved edit");
    close_clicked(NULL,&w,NULL); answer(&w,XmNcancelCallback,XmCR_CANCEL);
    assert(!XtAppGetExitFlag(app) && editor_dirty(&e));
    close_clicked(NULL,&w,NULL);
    answer(&w,discard ? XmNhelpCallback : XmNokCallback,discard ? XmCR_HELP : XmCR_OK);
    assert(XtAppGetExitFlag(app) && editor_dirty(&e) == discard);
    after = read_file(".config");
    assert((strcmp(before,after) == 0) == discard);
    free(before); free(after);
    XtDestroyWidget(shell); free(w.widgets); XtCloseDisplay(display); XtDestroyApplicationContext(app);
    test_cleanup(&e,directory);
}
int main(int argc, char** argv) {
    /* Motif caches display resources globally; run each exit path in a fresh process. */
    pid_t child = fork(); assert(child >= 0);
    if (!child) { run_test(argc,argv,true); return 0; }
    int status; assert(waitpid(child,&status,0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    run_test(argc,argv,false);
    puts("Motif editor tests passed"); return 0;
}
