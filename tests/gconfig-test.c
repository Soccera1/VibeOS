#define _GNU_SOURCE
#define CONFIG_GUI_TEST
#include "../tools/gconfig.c"
#include "config-fixture.h"
static gboolean respond(gpointer response) {
    GList* windows = gtk_window_list_toplevels();
    for (GList* p = windows; p; p = p->next)
        if (GTK_IS_MESSAGE_DIALOG(p->data)) gtk_dialog_response(GTK_DIALOG(p->data),GPOINTER_TO_INT(response));
    g_list_free(windows); return G_SOURCE_REMOVE;
}
static void mark_destroyed(GtkWidget* widget, gpointer data) {
    (void)widget; *(bool*)data = true;
}
int main(void) {
    assert(gtk_init_check(NULL,NULL));
    ConfigEditor e; char directory[] = "/tmp/vibeos-gconfig-test-XXXXXX"; test_setup(&e,directory);
    Window w; build_window(&w,&e); gtk_widget_show_all(w.window);
    while (gtk_events_pending()) gtk_main_iteration();
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w.widgets[0]),FALSE);
    assert(editor_dirty(&e) && !gtk_widget_get_sensitive(w.widgets[1]));
    assert(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w.widgets[1])));
    assert(save(&w));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w.widgets[0]),TRUE);
    assert(gtk_widget_get_sensitive(w.widgets[1]) && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w.widgets[1])));
    gtk_entry_set_text(GTK_ENTRY(w.widgets[2]),"invalid");
    char* before = read_file(".config"); assert(!editor_save(&e));
    char* after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
    gtk_entry_set_text(GTK_ENTRY(w.widgets[2]),"123");
    gtk_entry_set_text(GTK_ENTRY(w.widgets[3]),"0xff");
    gtk_entry_set_text(GTK_ENTRY(w.widgets[4]),"quoted \"text\" \\ path");
    assert(save(&w)); check_saved(&e);
    before = read_file(".config");
    gtk_entry_set_text(GTK_ENTRY(w.widgets[4]),"unsaved edit");
    g_idle_add(respond,GINT_TO_POINTER(GTK_RESPONSE_CANCEL));
    assert(confirm_close(w.window,NULL,&w)); assert(editor_dirty(&e));
    g_idle_add(respond,GINT_TO_POINTER(GTK_RESPONSE_NO));
    assert(!confirm_close(w.window,NULL,&w));
    after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
    g_idle_add(respond,GINT_TO_POINTER(GTK_RESPONSE_YES));
    assert(!confirm_close(w.window,NULL,&w)); assert(!editor_dirty(&e));
    bool closed = false;
    g_signal_connect(w.window,"destroy",G_CALLBACK(mark_destroyed),&closed);
    gtk_entry_set_text(GTK_ENTRY(w.widgets[4]),"close button edit");
    g_idle_add(respond,GINT_TO_POINTER(GTK_RESPONSE_CANCEL));
    close_clicked(NULL,&w); assert(!closed && editor_dirty(&e));
    g_idle_add(respond,GINT_TO_POINTER(GTK_RESPONSE_YES));
    close_clicked(NULL,&w); assert(closed && !editor_dirty(&e));
    g_free(w.widgets);
    test_cleanup(&e,directory); puts("GTK editor tests passed"); return 0;
}
