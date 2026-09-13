extern "C" {
#include "config_editor.h"
}
#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Scroll.H>
#include <FL/fl_ask.H>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

class Window : public Fl_Double_Window {
public:
    ConfigEditor* editor;
    std::vector<Fl_Widget*> widgets;
    Fl_Box* status;
    explicit Window(ConfigEditor* e) : Fl_Double_Window(850,700), editor(e), widgets(e->model.count,nullptr) {
        copy_label((std::string(e->model.mainmenu) + " — fconfig").c_str());
        auto* scroll = new Fl_Scroll(10,10,830,610);
        scroll->type(Fl_Scroll::BOTH);
        int y = 20;
        std::string menu;
        for (size_t i = 0; i < e->model.count; ++i) {
            Symbol* s = &e->model.symbols[i];
            if (!s->prompt || !*s->prompt) continue;
            const char* section = *s->menu ? s->menu : "General";
            if (menu != section) {
                menu = section;
                auto* heading = new Fl_Box(20,y,790,30);
                heading->copy_label(section);
                heading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
                heading->labelfont(FL_HELVETICA_BOLD);
                y += 40;
            }
            Fl_Widget* widget;
            if (!std::strcmp(s->type,"bool")) {
                auto* check = new Fl_Check_Button(20,y,790,32,s->prompt);
                check->value(bool_value(e->raw[i]));
                widget = check;
                y += 40;
            } else {
                auto* label = new Fl_Box(20,y,790,32,s->prompt);
                label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
                y += 32;
                auto* entry = new Fl_Input(30,y,770,30);
                entry->value(e->raw[i]);
                entry->when(FL_WHEN_CHANGED);
                widget = entry;
                y += 40;
            }
            char* help = editor_help(s); widget->copy_tooltip(help); std::free(help);
            widget->callback([](Fl_Widget* changed, void* data) {
                auto* self = static_cast<Window*>(data);
                for (size_t i = 0; i < self->widgets.size(); ++i) {
                    if (self->widgets[i] != changed) continue;
                    const char* value;
                    if (!std::strcmp(self->editor->model.symbols[i].type,"bool"))
                        value = static_cast<Fl_Check_Button*>(changed)->value() ? "y" : "n";
                    else value = static_cast<Fl_Input*>(changed)->value();
                    editor_set(self->editor,i,value);
                    self->refresh();
                    break;
                }
            },this);
            widgets[i] = widget;
        }
        scroll->end();
        status = new Fl_Box(10,625,830,25);
        status->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        auto* save_button = new Fl_Button(650,660,90,30,"Save");
        save_button->callback([](Fl_Widget*, void* data) { static_cast<Window*>(data)->save(); },this);
        auto* close_button = new Fl_Button(750,660,90,30,"Close");
        close_button->callback([](Fl_Widget*, void* data) { static_cast<Window*>(data)->close(); },this);
        callback([](Fl_Widget*, void* data) { static_cast<Window*>(data)->close(); },this);
        end(); resizable(scroll); size_range(850,400); refresh();
    }
    void refresh() {
        for (size_t i = 0; i < widgets.size(); ++i) {
            if (!widgets[i]) continue;
            Symbol* s = &editor->model.symbols[i];
            if (eval_depends(&editor->model,s->depends)) widgets[i]->activate();
            else widgets[i]->deactivate();
            if (!std::strcmp(s->type,"bool"))
                static_cast<Fl_Check_Button*>(widgets[i])->value(bool_value(s->value));
        }
        status->copy_label((std::string(editor->config) + (editor_dirty(editor) ? " — Modified" : "")).c_str());
        redraw();
    }
    bool save() {
        if (!editor_save(editor)) {
            fl_alert("%s",editor->error);
            return false;
        }
        refresh(); return true;
    }
    bool close() {
        if (editor_dirty(editor)) {
            int answer = fl_choice("Save configuration before closing?","Cancel","Discard","Save");
            if (answer != 1 && (answer != 2 || !save())) return false;
        }
        hide(); return true;
    }
};
#ifndef CONFIG_GUI_TEST
int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor,argc,argv);
    if (result) return result < 0 ? 2 : 0;
    int status;
    { Window window(&editor); window.show(); status = Fl::run(); }
    editor_free(&editor); return status;
}
#endif
