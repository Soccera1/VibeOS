#include "config_editor.h"
#include <tcl.h>
#include <tk.h>
#include <stdlib.h>
#include <string.h>

/* Pass all model text as Tcl objects: prompts and values are never scripts. */
static int config_command(ClientData data, Tcl_Interp* interp, int objc, Tcl_Obj* const objv[]) {
    ConfigEditor* e = data;
    static const char* commands[] = {"title", "path", "options", "set", "save", "dirty", NULL};
    enum { TITLE, PATH, OPTIONS, SET, SAVE, DIRTY };
    int command;
    if (objc < 2) {
        Tcl_WrongNumArgs(interp,1,objv,"subcommand ?args?"); return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp,objv[1],commands,"subcommand",TCL_EXACT,&command) != TCL_OK)
        return TCL_ERROR;
    if (objc != (command == SET ? 4 : 2)) {
        Tcl_WrongNumArgs(interp,2,objv,command == SET ? "index value" : ""); return TCL_ERROR;
    }
    switch (command) {
    case TITLE: Tcl_SetObjResult(interp,Tcl_NewStringObj(e->model.mainmenu,-1)); break;
    case PATH: Tcl_SetObjResult(interp,Tcl_NewStringObj(e->config,-1)); break;
    case DIRTY: Tcl_SetObjResult(interp,Tcl_NewBooleanObj(editor_dirty(e))); break;
    case SET: {
        int index;
        if (Tcl_GetIntFromObj(interp,objv[2],&index) != TCL_OK) return TCL_ERROR;
        if (index < 0 || (size_t)index >= e->model.count) {
            Tcl_SetObjResult(interp,Tcl_NewStringObj("Invalid symbol index",-1)); return TCL_ERROR;
        }
        editor_set(e,(size_t)index,Tcl_GetString(objv[3]));
        break;
    }
    case SAVE:
        if (!editor_save(e)) {
            Tcl_SetObjResult(interp,Tcl_NewStringObj(e->error,-1)); return TCL_ERROR;
        }
        break;
    case OPTIONS: {
        Tcl_Obj* options = Tcl_NewListObj(0,NULL);
        for (size_t i = 0; i < e->model.count; ++i) {
            Symbol* s = &e->model.symbols[i];
            if (!s->prompt || !*s->prompt) continue;
            char* help = editor_help(s);
            Tcl_Obj* fields[] = {
                Tcl_NewWideIntObj((Tcl_WideInt)i),
                Tcl_NewStringObj(*s->menu ? s->menu : "General",-1),
                Tcl_NewStringObj(s->prompt,-1), Tcl_NewStringObj(s->type,-1),
                Tcl_NewStringObj(!strcmp(s->type,"bool") ? s->value : e->raw[i],-1),
                Tcl_NewBooleanObj(eval_depends(&e->model,s->depends)), Tcl_NewStringObj(help,-1)
            };
            free(help);
            Tcl_ListObjAppendElement(interp,options,Tcl_NewListObj(7,fields));
        }
        Tcl_SetObjResult(interp,options);
        break;
    }
    }
    return TCL_OK;
}

static const char window_script[] =
"\n"
"wm title . \"[config title] — tkconfig\"\n"
"wm geometry . 850x700\n"
"set refreshing 0\n"
"array set values {}\n"
"array set widgets {}\n"
"proc refresh {} {\n"
"    global refreshing values widgets\n"
"    set refreshing 1\n"
"    foreach option [config options] {\n"
"        lassign $option i menu prompt type value enabled help\n"
"        if {![info exists widgets($i)]} continue\n"
"        $widgets($i) configure -state [expr {$enabled ? \"normal\" : \"disabled\"}]\n"
"        if {$type eq \"bool\"} {set values($i) $value}\n"
"    }\n"
"    .status configure -text \"[config path][expr {[config dirty] ? { — Modified} : {}}]\"\n"
"    set refreshing 0\n"
"}\n"
"proc changed {i args} {\n"
"    global refreshing values\n"
"    if {$refreshing} return\n"
"    config set $i $values($i)\n"
"    refresh\n"
"}\n"
"proc save {} {\n"
"    if {[catch {config save} error]} {\n"
"        tk_messageBox -parent . -icon error -type ok -title \"Cannot save configuration\" -message $error\n"
"        return 0\n"
"    }\n"
"    refresh\n"
"    return 1\n"
"}\n"
"proc close {} {\n"
"    if {[config dirty]} {\n"
"        set answer [tk_messageBox -parent . -icon question -type yesnocancel -default cancel -title \"Unsaved changes\" -message \"Save configuration before closing?\"]\n"
"        if {$answer eq \"cancel\" || ($answer eq \"yes\" && ![save])} return\n"
"    }\n"
"    destroy .\n"
"}\n"
"proc scroll {amount} {.scroll.canvas yview scroll $amount units}\n"
"ttk::frame .scroll\n"
"canvas .scroll.canvas -highlightthickness 0 -yscrollcommand {.scroll.bar set}\n"
"ttk::scrollbar .scroll.bar -orient vertical -command {.scroll.canvas yview}\n"
"pack .scroll.bar -side right -fill y\n"
"pack .scroll.canvas -side left -fill both -expand 1\n"
"pack .scroll -fill both -expand 1 -padx 12 -pady 12\n"
"ttk::frame .scroll.canvas.content\n"
".scroll.canvas create window 0 0 -anchor nw -window .scroll.canvas.content -tags content\n"
"bind .scroll.canvas.content <Configure> {.scroll.canvas configure -scrollregion [.scroll.canvas bbox all]}\n"
"bind .scroll.canvas <Configure> {.scroll.canvas itemconfigure content -width %w}\n"
"bind all <Button-4> {scroll -3}\n"
"bind all <Button-5> {scroll 3}\n"
"bind all <MouseWheel> {scroll [expr {%D > 0 ? -3 : 3}]}\n"
"set groups [dict create]\n"
"foreach option [config options] {\n"
"    lassign $option i menu prompt type value enabled help\n"
"    if {![dict exists $groups $menu]} {\n"
"        set group .scroll.canvas.content.g[dict size $groups]\n"
"        dict set groups $menu $group\n"
"        ttk::labelframe $group -text $menu -padding 10\n"
"        pack $group -fill x -pady 5\n"
"    }\n"
"    set group [dict get $groups $menu]\n"
"    set row $group.r$i\n"
"    ttk::frame $row\n"
"    pack $row -fill x -pady 3\n"
"    set values($i) $value\n"
"    if {$type eq \"bool\"} {\n"
"        ttk::checkbutton $row.value -text $prompt -variable values($i) -onvalue y -offvalue n\n"
"        pack $row.value -side left\n"
"    } else {\n"
"        ttk::label $row.label -text $prompt\n"
"        ttk::entry $row.value -textvariable values($i) -width 30\n"
"        pack $row.label -side left\n"
"        pack $row.value -side right\n"
"    }\n"
"    set widgets($i) $row.value\n"
"    bind $row.value <Enter> [list .help configure -text $help]\n"
"    bind $row.value <FocusIn> [list .help configure -text $help]\n"
"    trace add variable values($i) write [list changed $i]\n"
"}\n"
"ttk::label .help -text \"Hover over or focus an option for help.\" -anchor w -justify left -wraplength 800\n"
"pack .help -fill x -padx 12\n"
"bind . <Configure> {if {\"%W\" eq \".\"} {.help configure -wraplength [expr {max(100, %w - 24)}]}}\n"
"ttk::label .status -anchor w\n"
"pack .status -fill x -padx 12 -pady 6\n"
"ttk::frame .buttons\n"
"ttk::button .buttons.save -text Save -command save\n"
"ttk::button .buttons.close -text Close -command close\n"
"pack .buttons.close .buttons.save -side right -padx 4\n"
"pack .buttons -fill x -padx 8 -pady 8\n"
"wm protocol . WM_DELETE_WINDOW close\n"
"bind . <Control-s> {save}\n"
"refresh\n";

static int build_window(Tcl_Interp* interp, ConfigEditor* editor) {
    Tcl_CreateObjCommand(interp,"config",config_command,editor,NULL);
    return Tcl_EvalEx(interp,window_script,-1,TCL_EVAL_GLOBAL);
}

#ifndef CONFIG_GUI_TEST
int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor,argc,argv);
    if (result) return result < 0 ? 2 : 0;
    Tcl_FindExecutable(argv[0]);
    Tcl_Interp* interp = Tcl_CreateInterp();
    if (Tcl_Init(interp) != TCL_OK || Tk_Init(interp) != TCL_OK ||
        build_window(interp,&editor) != TCL_OK) {
        fprintf(stderr,"tkconfig: %s\nTk requires its runtime libraries and a graphical display.\n",
                Tcl_GetStringResult(interp));
        result = 1;
    } else {
        Tk_MainLoop();
    }
    Tcl_DeleteInterp(interp);
    Tcl_Finalize();
    editor_free(&editor);
    return result;
}
#endif
