#define CONFIG_GUI_TEST
#include "../tools/fconfig.cpp"
#include "config-fixture.h"

static bool answer_dialog(Fl_Group* group, const char* answer) {
    for (int i = 0; i < group->children(); ++i) {
        Fl_Widget* widget = group->child(i);
        if (auto* button = dynamic_cast<Fl_Button*>(widget)) {
            if (button->label() && !strcmp(button->label(),answer)) {
                button->do_callback(); return true;
            }
        }
        if (auto* child = dynamic_cast<Fl_Group*>(widget))
            if (answer_dialog(child,answer)) return true;
    }
    return false;
}
static bool close_with(Window& window, const char* answer) {
    Fl::add_timeout(0.05,[](void* data) {
        for (Fl_Window* w = Fl::first_window(); w; w = Fl::next_window(w))
            if (w->modal() && answer_dialog(w,static_cast<const char*>(data))) return;
        assert(false && "Close confirmation dialog missing");
    },const_cast<char*>(answer));
    return window.close();
}
int main() {
    ConfigEditor e; char directory[] = "/tmp/vibeos-fconfig-test-XXXXXX"; test_setup(&e,directory);
    {
        Window w(&e); w.show(); Fl::check();
        assert(!editor_dirty(&e) && access(".config",F_OK) != 0);
        assert(strstr(w.widgets[0]->tooltip(),"CONFIG_PARENT"));
        auto toggle = [&w](int i, bool value) {
            static_cast<Fl_Check_Button*>(w.widgets[i])->value(value);
            w.widgets[i]->do_callback();
        };
        auto enter = [&w](int i, const char* value) {
            static_cast<Fl_Input*>(w.widgets[i])->value(value);
            w.widgets[i]->do_callback();
        };
        toggle(0,false);
        assert(editor_dirty(&e) && !w.widgets[1]->active());
        assert(!static_cast<Fl_Check_Button*>(w.widgets[1])->value());
        assert(w.save()); toggle(0,true);
        assert(w.widgets[1]->active() && static_cast<Fl_Check_Button*>(w.widgets[1])->value());
        enter(2,"invalid");
        char* before = read_file(".config"); assert(!editor_save(&e));
        char* after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
        enter(2,"123"); enter(3,"0xff"); enter(4,"quoted \"text\" \\ path");
        assert(w.save()); check_saved(&e);
        before = read_file(".config"); enter(4,"unsaved edit");
        assert(!close_with(w,"Cancel")); assert(editor_dirty(&e) && w.shown());
        assert(close_with(w,"Discard")); assert(!w.shown());
        after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
        w.show(); assert(close_with(w,"Save")); assert(!editor_dirty(&e) && !w.shown());
    }
    test_cleanup(&e,directory); puts("FLTK editor tests passed"); return 0;
}
