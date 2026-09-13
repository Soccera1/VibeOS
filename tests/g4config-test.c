#define _GNU_SOURCE
#define CONFIG_GUI_TEST
#include "../tools/g4config.c"
#include "config-fixture.h"

static void respond(Window* w, int response) {
    assert(w->dialog);
    gtk_dialog_response(GTK_DIALOG(w->dialog),response);
}
static void open_window(Window* w, ConfigEditor* e) {
    build_window(w,e);
    gtk_window_present(GTK_WINDOW(w->window));
    while (g_main_context_pending(NULL)) g_main_context_iteration(NULL,FALSE);
}
int main(void) {
    assert(gtk_init_check());
    ConfigEditor e; char directory[] = "/tmp/vibeos-g4config-test-XXXXXX"; test_setup(&e,directory);
    Window w; open_window(&w,&e);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(w.widgets[0]),FALSE);
    assert(editor_dirty(&e) && !gtk_widget_get_sensitive(w.widgets[1]));
    assert(!gtk_check_button_get_active(GTK_CHECK_BUTTON(w.widgets[1])));
    save_clicked(NULL,&w); assert(!editor_dirty(&e));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(w.widgets[0]),TRUE);
    assert(gtk_widget_get_sensitive(w.widgets[1]) && gtk_check_button_get_active(GTK_CHECK_BUTTON(w.widgets[1])));
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[2]),"invalid");
    char* before = read_file(".config"); assert(!save(&w));
    respond(&w,GTK_RESPONSE_CLOSE); assert(!w.dialog && !w.closed);
    char* after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[2]),"123");
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[3]),"0xff");
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[4]),"quoted \"text\" \\ path");
    assert(save(&w)); check_saved(&e);
    before = read_file(".config");
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[4]),"unsaved edit");
    close_clicked(NULL,&w);
    GtkWidget* prompt = w.dialog;
    close_clicked(NULL,&w); assert(w.dialog == prompt);
    respond(&w,GTK_RESPONSE_CANCEL); assert(!w.closed && editor_dirty(&e));
    close_clicked(NULL,&w); respond(&w,GTK_RESPONSE_DELETE_EVENT); assert(!w.closed);
    close_clicked(NULL,&w); respond(&w,GTK_RESPONSE_NO); assert(w.closed && editor_dirty(&e));
    after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
    g_free(w.widgets);

    open_window(&w,&e);
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[2]),"invalid");
    gtk_window_close(GTK_WINDOW(w.window)); respond(&w,GTK_RESPONSE_YES);
    assert(!w.closed && editor_dirty(&e) && w.dialog);
    respond(&w,GTK_RESPONSE_CLOSE);
    gtk_editable_set_text(GTK_EDITABLE(w.widgets[2]),"123");
    gtk_window_close(GTK_WINDOW(w.window)); respond(&w,GTK_RESPONSE_YES);
    assert(w.closed && !editor_dirty(&e));
    g_free(w.widgets);
    open_window(&w,&e);
    close_clicked(NULL,&w); assert(w.closed && !w.dialog);
    g_free(w.widgets);
    test_cleanup(&e,directory); puts("GTK 4 editor tests passed"); return 0;
}
