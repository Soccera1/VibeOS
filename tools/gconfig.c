#include "config_editor.h"
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ConfigEditor* editor;
    GtkWidget *window, *status;
    GtkWidget** widgets;
    bool refreshing;
} Window;
static void refresh(Window* w) {
    w->refreshing = true;
    ConfigEditor* e = w->editor;
    for (size_t i = 0; i < e->model.count; ++i) {
        Symbol* s = &e->model.symbols[i];
        if (!w->widgets[i]) continue;
        gtk_widget_set_sensitive(w->widgets[i],eval_depends(&e->model,s->depends));
        if (!strcmp(s->type,"bool"))
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->widgets[i]),bool_value(s->value));
    }
    char* status = g_strdup_printf("%s%s",e->config,editor_dirty(e) ? " — Modified" : "");
    gtk_label_set_text(GTK_LABEL(w->status),status);
    g_free(status);
    w->refreshing = false;
}
static void changed(GtkWidget* widget, gpointer data) {
    Window* w = data;
    if (w->refreshing) return;
    size_t i = GPOINTER_TO_SIZE(g_object_get_data(G_OBJECT(widget),"symbol-index"));
    const char* value = GTK_IS_TOGGLE_BUTTON(widget) ?
        (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)) ? "y" : "n") :
        gtk_entry_get_text(GTK_ENTRY(widget));
    editor_set(w->editor,i,value);
    refresh(w);
}
static bool save(Window* w) {
    if (!editor_save(w->editor)) {
        GtkWidget* dialog = gtk_message_dialog_new(GTK_WINDOW(w->window),GTK_DIALOG_MODAL,
            GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,"Cannot save configuration");
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog),"%s",w->editor->error);
        gtk_dialog_run(GTK_DIALOG(dialog)); gtk_widget_destroy(dialog);
        return false;
    }
    refresh(w); return true;
}
static gboolean confirm_close(GtkWidget* widget, GdkEvent* event, gpointer data) {
    (void)widget; (void)event;
    Window* w = data;
    if (!editor_dirty(w->editor)) return FALSE;
    GtkWidget* dialog = gtk_message_dialog_new(GTK_WINDOW(w->window),GTK_DIALOG_MODAL,
        GTK_MESSAGE_QUESTION,GTK_BUTTONS_NONE,"Save configuration before closing?");
    gtk_dialog_add_buttons(GTK_DIALOG(dialog),"Cancel",GTK_RESPONSE_CANCEL,"Discard",GTK_RESPONSE_NO,
                           "Save",GTK_RESPONSE_YES,NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog),GTK_RESPONSE_CANCEL);
    int answer = gtk_dialog_run(GTK_DIALOG(dialog)); gtk_widget_destroy(dialog);
    return answer != GTK_RESPONSE_NO && (answer != GTK_RESPONSE_YES || !save(w));
}
static void save_clicked(GtkButton* button, gpointer data) { (void)button; save(data); }
static void close_clicked(GtkButton* button, gpointer data) {
    (void)button; gtk_window_close(GTK_WINDOW(((Window*)data)->window));
}
static void destroyed(GtkWidget* widget, gpointer data) {
    (void)widget; (void)data;
    if (gtk_main_level()) gtk_main_quit();
}
static void build_window(Window* w, ConfigEditor* e) {
    memset(w,0,sizeof(*w)); w->editor = e;
    w->widgets = g_new0(GtkWidget*,e->model.count);
    w->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char* title = g_strdup_printf("%s — gconfig",e->model.mainmenu);
    gtk_window_set_title(GTK_WINDOW(w->window),title); g_free(title);
    gtk_window_set_default_size(GTK_WINDOW(w->window),850,700);
    gtk_container_set_border_width(GTK_CONTAINER(w->window),12);
    GtkWidget* layout = gtk_box_new(GTK_ORIENTATION_VERTICAL,10);
    gtk_container_add(GTK_CONTAINER(w->window),layout);
    GtkWidget* scroll = gtk_scrolled_window_new(NULL,NULL);
    gtk_box_pack_start(GTK_BOX(layout),scroll,TRUE,TRUE,0);
    GtkWidget* content = gtk_box_new(GTK_ORIENTATION_VERTICAL,12);
    gtk_container_add(GTK_CONTAINER(scroll),content);
    GHashTable* groups = g_hash_table_new(g_str_hash,g_str_equal);
    for (size_t i = 0; i < e->model.count; ++i) {
        Symbol* s = &e->model.symbols[i];
        if (!s->prompt || !*s->prompt) continue;
        const char* menu = *s->menu ? s->menu : "General";
        GtkWidget* group = g_hash_table_lookup(groups,menu);
        if (!group) {
            GtkWidget* frame = gtk_frame_new(menu);
            group = gtk_box_new(GTK_ORIENTATION_VERTICAL,6);
            gtk_container_set_border_width(GTK_CONTAINER(group),10);
            gtk_container_add(GTK_CONTAINER(frame),group);
            gtk_box_pack_start(GTK_BOX(content),frame,FALSE,FALSE,0);
            g_hash_table_insert(groups,(gpointer)menu,group);
        }
        GtkWidget *widget, *row;
        if (!strcmp(s->type,"bool")) {
            widget = gtk_check_button_new_with_label(s->prompt); row = widget;
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget),bool_value(e->raw[i]));
            g_signal_connect(widget,"toggled",G_CALLBACK(changed),w);
        } else {
            row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL,12);
            GtkWidget* label = gtk_label_new(s->prompt);
            gtk_label_set_xalign(GTK_LABEL(label),0);
            gtk_box_pack_start(GTK_BOX(row),label,TRUE,TRUE,0);
            widget = gtk_entry_new(); gtk_entry_set_text(GTK_ENTRY(widget),e->raw[i]);
            gtk_box_pack_end(GTK_BOX(row),widget,FALSE,FALSE,0);
            g_signal_connect(widget,"changed",G_CALLBACK(changed),w);
        }
        g_object_set_data(G_OBJECT(widget),"symbol-index",GSIZE_TO_POINTER(i));
        char* help = editor_help(s); gtk_widget_set_tooltip_text(widget,help); free(help);
        w->widgets[i] = widget;
        gtk_box_pack_start(GTK_BOX(group),row,FALSE,FALSE,0);
    }
    g_hash_table_destroy(groups);
    w->status = gtk_label_new(NULL); gtk_label_set_xalign(GTK_LABEL(w->status),0);
    gtk_box_pack_start(GTK_BOX(layout),w->status,FALSE,FALSE,0);
    GtkWidget* buttons = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(buttons),GTK_BUTTONBOX_END);
    GtkWidget *save_button = gtk_button_new_with_label("Save"), *close_button = gtk_button_new_with_label("Close");
    gtk_container_add(GTK_CONTAINER(buttons),save_button); gtk_container_add(GTK_CONTAINER(buttons),close_button);
    gtk_box_pack_start(GTK_BOX(layout),buttons,FALSE,FALSE,0);
    g_signal_connect(save_button,"clicked",G_CALLBACK(save_clicked),w);
    g_signal_connect(close_button,"clicked",G_CALLBACK(close_clicked),w);
    g_signal_connect(w->window,"delete-event",G_CALLBACK(confirm_close),w);
    g_signal_connect(w->window,"destroy",G_CALLBACK(destroyed),w);
    refresh(w);
}
#ifndef CONFIG_GUI_TEST
int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor,argc,argv);
    if (result) return result < 0 ? 2 : 0;
    if (!gtk_init_check(NULL,NULL)) {
        fprintf(stderr,"gconfig requires a graphical display (DISPLAY or WAYLAND_DISPLAY).\n");
        editor_free(&editor); return 1;
    }
    Window window; build_window(&window,&editor);
    gtk_widget_show_all(window.window); gtk_main();
    g_free(window.widgets); editor_free(&editor); return 0;
}
#endif
