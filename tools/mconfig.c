#include "config_editor.h"
#include <Xm/Form.h>
#include <Xm/Frame.h>
#include <Xm/Label.h>
#include <Xm/MessageB.h>
#include <Xm/Protocols.h>
#include <Xm/PushB.h>
#include <Xm/RowColumn.h>
#include <Xm/ScrolledW.h>
#include <Xm/TextF.h>
#include <Xm/ToggleB.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ConfigEditor* editor;
    XtAppContext app;
    Widget window, status, close_dialog, error_dialog;
    Widget* widgets;
    bool refreshing;
} ConfigWindow;

static void set_label(Widget widget, const char* text) {
    XmString label = XmStringCreateLocalized((char*)text);
    XtVaSetValues(widget,XmNlabelString,label,NULL);
    XmStringFree(label);
}
static Widget labeled(Widget parent, const char* name, WidgetClass class, const char* text) {
    Widget widget = XtVaCreateManagedWidget(name,class,parent,NULL);
    set_label(widget,text);
    return widget;
}
static void refresh(ConfigWindow* w) {
    w->refreshing = true;
    ConfigEditor* e = w->editor;
    for (size_t i = 0; i < e->model.count; ++i) {
        Symbol* s = &e->model.symbols[i];
        if (!w->widgets[i]) continue;
        XtSetSensitive(w->widgets[i],eval_depends(&e->model,s->depends));
        if (!strcmp(s->type,"bool"))
            XmToggleButtonSetState(w->widgets[i],bool_value(s->value),False);
    }
    size_t size = strlen(e->config) + 32;
    char* status = malloc(size);
    if (!status) { perror("malloc"); exit(1); }
    snprintf(status,size,"%s%s",e->config,editor_dirty(e) ? " - Modified" : "");
    set_label(w->status,status); free(status);
    w->refreshing = false;
}
static void changed(Widget widget, XtPointer data, XtPointer call) {
    (void)call;
    ConfigWindow* w = data;
    if (w->refreshing) return;
    /* The widget array also maps callbacks to model indices without integer casts. */
    for (size_t i = 0; i < w->editor->model.count; ++i) {
        if (w->widgets[i] != widget) continue;
        if (XmIsToggleButton(widget))
            editor_set(w->editor,i,XmToggleButtonGetState(widget) ? "y" : "n");
        else {
            char* value = XmTextFieldGetString(widget);
            editor_set(w->editor,i,value); XtFree(value);
        }
        refresh(w); break;
    }
}
static void dismiss_error(Widget widget, XtPointer data, XtPointer call) {
    (void)call;
    ConfigWindow* w = data;
    w->error_dialog = NULL;
    XtDestroyWidget(widget);
}
static bool save(ConfigWindow* w) {
    if (!editor_save(w->editor)) {
        if (!w->error_dialog) {
            w->error_dialog = XmCreateErrorDialog(w->window,"saveError",NULL,0);
            XtVaSetValues(w->error_dialog,XmNdialogStyle,XmDIALOG_FULL_APPLICATION_MODAL,NULL);
            XtUnmanageChild(XtNameToWidget(w->error_dialog,"Cancel"));
            XtUnmanageChild(XtNameToWidget(w->error_dialog,"Help"));
            XtAddCallback(w->error_dialog,XmNokCallback,dismiss_error,w);
        }
        XmString message = XmStringCreateLocalized(w->editor->error);
        XtVaSetValues(w->error_dialog,XmNmessageString,message,NULL);
        XmStringFree(message);
        XtManageChild(w->error_dialog);
        return false;
    }
    refresh(w); return true;
}
static void save_clicked(Widget widget, XtPointer data, XtPointer call) {
    (void)widget; (void)call; save(data);
}
static void close_answer(Widget widget, XtPointer data, XtPointer call) {
    ConfigWindow* w = data;
    XmAnyCallbackStruct* answer = call;
    int reason = answer->reason;
    w->close_dialog = NULL;
    XtDestroyWidget(widget);
    if (reason == XmCR_HELP || (reason == XmCR_OK && save(w)))
        XtAppSetExitFlag(w->app);
}
static void close_clicked(Widget widget, XtPointer data, XtPointer call) {
    (void)widget; (void)call;
    ConfigWindow* w = data;
    if (!editor_dirty(w->editor)) { XtAppSetExitFlag(w->app); return; }
    if (!w->close_dialog) {
        w->close_dialog = XmCreateQuestionDialog(w->window,"unsavedChanges",NULL,0);
        XmString message = XmStringCreateLocalized("Save configuration before closing?");
        XtVaSetValues(w->close_dialog,XmNmessageString,message,
            XmNdialogStyle,XmDIALOG_FULL_APPLICATION_MODAL,XmNautoUnmanage,False,
            XmNdefaultButtonType,XmDIALOG_CANCEL_BUTTON,NULL);
        XmStringFree(message);
        set_label(XtNameToWidget(w->close_dialog,"OK"),"Save");
        set_label(XtNameToWidget(w->close_dialog,"Help"),"Discard");
        XtAddCallback(w->close_dialog,XmNokCallback,close_answer,w);
        XtAddCallback(w->close_dialog,XmNcancelCallback,close_answer,w);
        XtAddCallback(w->close_dialog,XmNhelpCallback,close_answer,w);
    }
    XtManageChild(w->close_dialog);
}
static void build_window(ConfigWindow* w, ConfigEditor* e, XtAppContext app, Widget shell) {
    memset(w,0,sizeof(*w)); w->editor = e; w->app = app; w->window = shell;
    w->widgets = calloc(e->model.count + 1,sizeof(*w->widgets));
    Widget* groups = calloc(e->model.count + 1,sizeof(*groups));
    if (!w->widgets || !groups) { perror("calloc"); exit(1); }
    size_t size = strlen(e->model.mainmenu) + 16;
    char* title = malloc(size);
    if (!title) { perror("malloc"); exit(1); }
    snprintf(title,size,"%s - mconfig",e->model.mainmenu);
    XtVaSetValues(shell,XmNtitle,title,XmNwidth,850,XmNheight,700,
                  XmNdeleteResponse,XmDO_NOTHING,NULL);
    free(title);
    Widget form = XtVaCreateManagedWidget("layout",xmFormWidgetClass,shell,
                                          XmNmarginWidth,12,XmNmarginHeight,12,NULL);
    Widget buttons = XtVaCreateManagedWidget("buttons",xmRowColumnWidgetClass,form,
        XmNorientation,XmHORIZONTAL,XmNpacking,XmPACK_TIGHT,
        XmNbottomAttachment,XmATTACH_FORM,XmNrightAttachment,XmATTACH_FORM,NULL);
    Widget save_button = labeled(buttons,"save",xmPushButtonWidgetClass,"Save");
    Widget close_button = labeled(buttons,"close",xmPushButtonWidgetClass,"Close");
    w->status = XtVaCreateManagedWidget("status",xmLabelWidgetClass,form,
        XmNalignment,XmALIGNMENT_BEGINNING,XmNleftAttachment,XmATTACH_FORM,
        XmNrightAttachment,XmATTACH_FORM,XmNbottomAttachment,XmATTACH_WIDGET,
        XmNbottomWidget,buttons,XmNbottomOffset,8,NULL);
    Widget scroll = XtVaCreateManagedWidget("scroll",xmScrolledWindowWidgetClass,form,
        XmNscrollingPolicy,XmAUTOMATIC,XmNtopAttachment,XmATTACH_FORM,
        XmNleftAttachment,XmATTACH_FORM,XmNrightAttachment,XmATTACH_FORM,
        XmNbottomAttachment,XmATTACH_WIDGET,XmNbottomWidget,w->status,XmNbottomOffset,8,NULL);
    Widget content = XtVaCreateManagedWidget("options",xmRowColumnWidgetClass,scroll,
        XmNorientation,XmVERTICAL,XmNspacing,12,NULL);
    for (size_t i = 0; i < e->model.count; ++i) {
        Symbol* s = &e->model.symbols[i];
        if (!s->prompt || !*s->prompt) continue;
        Widget group = NULL;
        for (size_t j = 0; j < i; ++j)
            if (groups[j] && !strcmp(e->model.symbols[j].menu,s->menu)) { group = groups[j]; break; }
        if (!group) {
            Widget frame = XtVaCreateManagedWidget("menu",xmFrameWidgetClass,content,NULL);
            Widget label = labeled(frame,"title",xmLabelWidgetClass,*s->menu ? s->menu : "General");
            XtVaSetValues(label,XmNchildType,XmFRAME_TITLE_CHILD,NULL);
            group = XtVaCreateManagedWidget("group",xmRowColumnWidgetClass,frame,
                XmNorientation,XmVERTICAL,XmNmarginWidth,10,XmNmarginHeight,10,NULL);
        }
        groups[i] = group;
        Widget widget;
        if (!strcmp(s->type,"bool")) {
            widget = labeled(group,"option",xmToggleButtonWidgetClass,s->prompt);
            XtVaSetValues(widget,XmNalignment,XmALIGNMENT_BEGINNING,NULL);
        } else {
            Widget row = XtVaCreateManagedWidget("row",xmRowColumnWidgetClass,group,
                XmNorientation,XmHORIZONTAL,XmNpacking,XmPACK_TIGHT,NULL);
            labeled(row,"prompt",xmLabelWidgetClass,s->prompt);
            widget = XtVaCreateManagedWidget("value",xmTextFieldWidgetClass,row,
                                             XmNvalue,e->raw[i],XmNcolumns,28,NULL);
        }
        w->widgets[i] = widget;
        char* help = editor_help(s);
        XmString tooltip = XmStringCreateLocalized(help);
        XtVaSetValues(widget,XmNtoolTipString,tooltip,NULL);
        XmStringFree(tooltip); free(help);
        XtAddCallback(widget,XmNvalueChangedCallback,changed,w);
    }
    free(groups);
    XtAddCallback(save_button,XmNactivateCallback,save_clicked,w);
    XtAddCallback(close_button,XmNactivateCallback,close_clicked,w);
    Atom wm_delete = XInternAtom(XtDisplay(shell),"WM_DELETE_WINDOW",False);
    XmAddWMProtocolCallback(shell,wm_delete,close_clicked,w);
    refresh(w);
}
#ifndef CONFIG_GUI_TEST
int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor,argc,argv);
    if (result) return result < 0 ? 2 : 0;
    XtToolkitInitialize();
    XtAppContext app = XtCreateApplicationContext();
    int xt_argc = 1;
    Display* display = XtOpenDisplay(app,NULL,"mconfig","Mconfig",NULL,0,&xt_argc,argv);
    if (!display) {
        fprintf(stderr,"mconfig requires an X11 display (DISPLAY).\n");
        XtDestroyApplicationContext(app); editor_free(&editor); return 1;
    }
    Widget shell = XtAppCreateShell("mconfig","Mconfig",applicationShellWidgetClass,display,NULL,0);
    ConfigWindow window; build_window(&window,&editor,app,shell);
    XtRealizeWidget(shell); XtAppMainLoop(app);
    XtDestroyWidget(shell); free(window.widgets);
    XtCloseDisplay(display); XtDestroyApplicationContext(app);
    editor_free(&editor); return 0;
}
#endif
