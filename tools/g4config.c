#include "config_editor.h"
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

static void margins(GtkWidget* widget, int size) {
    gtk_widget_set_margin_start(widget,size);
    gtk_widget_set_margin_end(widget,size);
    gtk_widget_set_margin_top(widget,size);
    gtk_widget_set_margin_bottom(widget,size);
}

typedef struct {
    ConfigEditor* editor;
    GtkWidget *window, *status, *dialog;
    GtkWidget** widgets;
    bool refreshing, closed;
} Window;
static void refresh(Window* w) {
    w->refreshing = true;
    ConfigEditor* e = w->editor;
    for (size_t i = 0; i < e->model.count; ++i) {
        Symbol* s = &e->model.symbols[i];
        if (!w->widgets[i]) continue;
        gtk_widget_set_sensitive(w->widgets[i],eval_depends(&e->model,s->depends));
        if (!strcmp(s->type,"bool"))
            gtk_check_button_set_active(GTK_CHECK_BUTTON(w->widgets[i]),bool_value(s->value));
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
    const char* value = GTK_IS_CHECK_BUTTON(widget) ?
        (gtk_check_button_get_active(GTK_CHECK_BUTTON(widget)) ? "y" : "n") :
        gtk_editable_get_text(GTK_EDITABLE(widget));
    editor_set(w->editor,i,value);
    refresh(w);
}
static void dismiss_dialog(GtkDialog* dialog, int response, gpointer data) {
    (void)response;
    Window* w = data;
    w->dialog = NULL;
    gtk_window_destroy(GTK_WINDOW(dialog));
}
static bool save(Window* w) {
    if (!editor_save(w->editor)) {
        if (w->dialog) return false;
        w->dialog = gtk_message_dialog_new(GTK_WINDOW(w->window),GTK_DIALOG_MODAL,
            GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,"Cannot save configuration");
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(w->dialog),"%s",w->editor->error);
        g_signal_connect(w->dialog,"response",G_CALLBACK(dismiss_dialog),w);
        gtk_window_present(GTK_WINDOW(w->dialog));
        return false;
    }
    refresh(w); return true;
}
static void finish_close(Window* w) {
    w->closed = true;
    gtk_window_destroy(GTK_WINDOW(w->window));
}
static void close_response(GtkDialog* dialog, int response, gpointer data) {
    Window* w = data;
    dismiss_dialog(dialog,response,w);
    if (response == GTK_RESPONSE_NO || (response == GTK_RESPONSE_YES && save(w)))
        finish_close(w);
}
static gboolean confirm_close(GtkWindow* window, gpointer data) {
    (void)window;
    Window* w = data;
    if (w->dialog) {
        gtk_window_present(GTK_WINDOW(w->dialog));
        return TRUE;
    }
    if (!editor_dirty(w->editor)) {
        finish_close(w);
        return TRUE;
    }
    w->dialog = gtk_message_dialog_new(GTK_WINDOW(w->window),GTK_DIALOG_MODAL,
        GTK_MESSAGE_QUESTION,GTK_BUTTONS_NONE,"Save configuration before closing?");
    gtk_dialog_add_buttons(GTK_DIALOG(w->dialog),"Cancel",GTK_RESPONSE_CANCEL,"Discard",GTK_RESPONSE_NO,
                           "Save",GTK_RESPONSE_YES,NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(w->dialog),GTK_RESPONSE_CANCEL);
    g_signal_connect(w->dialog,"response",G_CALLBACK(close_response),w);
    gtk_window_present(GTK_WINDOW(w->dialog));
    return TRUE;
}
static void save_clicked(GtkButton* button, gpointer data) { (void)button; save(data); }
static void close_clicked(GtkButton* button, gpointer data) {
    (void)button;
    Window* w = data;
    gtk_window_close(GTK_WINDOW(w->window));
}
static void build_window(Window* w, ConfigEditor* e) {
    memset(w,0,sizeof(*w)); w->editor = e;
    w->widgets = g_new0(GtkWidget*,e->model.count);
    w->window = gtk_window_new();
    char* title = g_strdup_printf("%s — g4config",e->model.mainmenu);
    gtk_window_set_title(GTK_WINDOW(w->window),title); g_free(title);
    gtk_window_set_default_size(GTK_WINDOW(w->window),850,700);
    GtkWidget* layout = gtk_box_new(GTK_ORIENTATION_VERTICAL,10);
    margins(layout,12);
    gtk_window_set_child(GTK_WINDOW(w->window),layout);
    GtkWidget* scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC,GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll,TRUE);
    gtk_box_append(GTK_BOX(layout),scroll);
    GtkWidget* content = gtk_box_new(GTK_ORIENTATION_VERTICAL,12);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),content);
    GHashTable* groups = g_hash_table_new(g_str_hash,g_str_equal);
    for (size_t i = 0; i < e->model.count; ++i) {
        Symbol* s = &e->model.symbols[i];
        if (!s->prompt || !*s->prompt) continue;
        const char* menu = *s->menu ? s->menu : "General";
        GtkWidget* group = g_hash_table_lookup(groups,menu);
        if (!group) {
            GtkWidget* frame = gtk_frame_new(menu);
            group = gtk_box_new(GTK_ORIENTATION_VERTICAL,6);
            margins(group,10);
            gtk_frame_set_child(GTK_FRAME(frame),group);
            gtk_box_append(GTK_BOX(content),frame);
            g_hash_table_insert(groups,(gpointer)menu,group);
        }
        GtkWidget *widget, *row;
        if (!strcmp(s->type,"bool")) {
            widget = gtk_check_button_new_with_label(s->prompt); row = widget;
            gtk_check_button_set_active(GTK_CHECK_BUTTON(widget),bool_value(e->raw[i]));
            g_signal_connect(widget,"toggled",G_CALLBACK(changed),w);
        } else {
            row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL,12);
            GtkWidget* label = gtk_label_new(s->prompt);
            gtk_label_set_xalign(GTK_LABEL(label),0);
            gtk_widget_set_hexpand(label,TRUE);
            gtk_box_append(GTK_BOX(row),label);
            widget = gtk_entry_new(); gtk_editable_set_text(GTK_EDITABLE(widget),e->raw[i]);
            gtk_box_append(GTK_BOX(row),widget);
            g_signal_connect(widget,"changed",G_CALLBACK(changed),w);
        }
        g_object_set_data(G_OBJECT(widget),"symbol-index",GSIZE_TO_POINTER(i));
        char* help = editor_help(s); gtk_widget_set_tooltip_text(widget,help); free(help);
        w->widgets[i] = widget;
        gtk_box_append(GTK_BOX(group),row);
    }
    g_hash_table_destroy(groups);
    w->status = gtk_label_new(NULL); gtk_label_set_xalign(GTK_LABEL(w->status),0);
    gtk_box_append(GTK_BOX(layout),w->status);
    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);
    gtk_widget_set_halign(buttons,GTK_ALIGN_END);
    GtkWidget *save_button = gtk_button_new_with_label("Save"), *close_button = gtk_button_new_with_label("Close");
    gtk_box_append(GTK_BOX(buttons),save_button); gtk_box_append(GTK_BOX(buttons),close_button);
    gtk_box_append(GTK_BOX(layout),buttons);
    g_signal_connect(save_button,"clicked",G_CALLBACK(save_clicked),w);
    g_signal_connect(close_button,"clicked",G_CALLBACK(close_clicked),w);
    g_signal_connect(w->window,"close-request",G_CALLBACK(confirm_close),w);
    refresh(w);
}
#ifndef CONFIG_GUI_TEST
int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor,argc,argv);
    if (result) return result < 0 ? 2 : 0;
    if (!gtk_init_check()) {
        fprintf(stderr,"g4config requires a graphical display (DISPLAY or WAYLAND_DISPLAY).\n");
        editor_free(&editor); return 1;
    }
    Window window; build_window(&window,&editor);
    gtk_window_present(GTK_WINDOW(window.window));
    while (!window.closed) g_main_context_iteration(NULL,TRUE);
    g_free(window.widgets); editor_free(&editor); return 0;
}
#endif
