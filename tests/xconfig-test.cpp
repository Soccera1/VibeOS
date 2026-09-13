#define CONFIG_GUI_TEST
#include "../tools/xconfig.cpp"
#include "config-fixture.h"
#include <QTimer>
static bool close_with(Window& w, QMessageBox::StandardButton answer) {
    QTimer::singleShot(0,[answer] {
        for (auto* widget : QApplication::topLevelWidgets())
            if (auto* box = qobject_cast<QMessageBox*>(widget)) box->button(answer)->click();
    });
    QCloseEvent event; w.closeEvent(&event); return event.isAccepted();
}
int main(int argc, char** argv) {
    QApplication app(argc,argv);
    ConfigEditor e; char directory[] = "/tmp/vibeos-xconfig-test-XXXXXX"; test_setup(&e,directory);
    {
        Window w(&e); w.show(); app.processEvents();
        auto toggle = [&w](int i, bool value) { qobject_cast<QCheckBox*>(w.widgets[i])->setChecked(value); };
        auto enter = [&w](int i, const char* value) { qobject_cast<QLineEdit*>(w.widgets[i])->setText(value); };
        toggle(0,false);
        assert(editor_dirty(&e) && !w.widgets[1]->isEnabled());
        assert(!qobject_cast<QCheckBox*>(w.widgets[1])->isChecked());
        assert(w.save()); toggle(0,true);
        assert(w.widgets[1]->isEnabled() && qobject_cast<QCheckBox*>(w.widgets[1])->isChecked());
        enter(2,"invalid");
        char* before = read_file(".config"); assert(!editor_save(&e));
        char* after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
        enter(2,"123"); enter(3,"0xff"); enter(4,"quoted \"text\" \\ path");
        assert(w.save()); check_saved(&e);
        before = read_file(".config"); enter(4,"unsaved edit");
        assert(!close_with(w,QMessageBox::Cancel)); assert(editor_dirty(&e));
        assert(close_with(w,QMessageBox::Discard));
        after = read_file(".config"); assert(!strcmp(before,after)); free(before); free(after);
        assert(close_with(w,QMessageBox::Save)); assert(!editor_dirty(&e));
    }
    test_cleanup(&e,directory); puts("Qt editor tests passed"); return 0;
}
