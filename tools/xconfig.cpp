extern "C" {
#include "config_editor.h"
}
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QVBoxLayout>
#include <vector>
#include <cstdlib>
#include <cstring>

class Window : public QWidget {
public:
    ConfigEditor* editor;
    std::vector<QWidget*> widgets;
    QLabel* status;
    explicit Window(ConfigEditor* e) : editor(e), widgets(e->model.count,nullptr) {
        setWindowTitle(QString::fromUtf8(e->model.mainmenu) + " — xconfig");
        resize(850,700);
        auto* layout = new QVBoxLayout(this);
        auto* scroll = new QScrollArea;
        scroll->setWidgetResizable(true);
        auto* content = new QWidget;
        auto* form = new QVBoxLayout(content);
        QMap<QString,QFormLayout*> groups;
        for (size_t i = 0; i < e->model.count; ++i) {
            Symbol* s = &e->model.symbols[i];
            if (!s->prompt || !*s->prompt) continue;
            QString menu = QString::fromUtf8(*s->menu ? s->menu : "General");
            if (!groups.contains(menu)) {
                auto* box = new QGroupBox(menu);
                groups[menu] = new QFormLayout(box);
                form->addWidget(box);
            }
            QWidget* widget;
            if (!std::strcmp(s->type,"bool")) {
                auto* check = new QCheckBox(QString::fromUtf8(s->prompt));
                check->setChecked(bool_value(e->raw[i]));
                connect(check,&QCheckBox::toggled,this,[this,i](bool value) {
                    editor_set(editor,i,value ? "y" : "n"); refresh();
                });
                groups[menu]->addRow(check); widget = check;
            } else {
                auto* entry = new QLineEdit(QString::fromUtf8(e->raw[i]));
                connect(entry,&QLineEdit::textChanged,this,[this,i](const QString& value) {
                    editor_set(editor,i,value.toUtf8().constData()); refresh();
                });
                groups[menu]->addRow(QString::fromUtf8(s->prompt),entry); widget = entry;
            }
            char* help = editor_help(s); widget->setToolTip(QString::fromUtf8(help)); std::free(help);
            widgets[i] = widget;
        }
        form->addStretch(); scroll->setWidget(content); layout->addWidget(scroll);
        status = new QLabel; layout->addWidget(status);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Close);
        connect(buttons->button(QDialogButtonBox::Save),&QPushButton::clicked,this,[this] { save(); });
        connect(buttons,&QDialogButtonBox::rejected,this,&QWidget::close);
        layout->addWidget(buttons); refresh();
    }
    void refresh() {
        for (size_t i = 0; i < editor->model.count; ++i) {
            if (!widgets[i]) continue;
            Symbol* s = &editor->model.symbols[i];
            widgets[i]->setEnabled(eval_depends(&editor->model,s->depends));
            if (auto* check = qobject_cast<QCheckBox*>(widgets[i])) {
                QSignalBlocker blocker(check); check->setChecked(bool_value(s->value));
            }
        }
        status->setText(QString::fromUtf8(editor->config) + (editor_dirty(editor) ? " — Modified" : ""));
    }
    bool save() {
        if (!editor_save(editor)) {
            QMessageBox::warning(this,"Cannot save configuration",QString::fromUtf8(editor->error));
            return false;
        }
        refresh(); return true;
    }
    void closeEvent(QCloseEvent* event) override {
        if (editor_dirty(editor)) {
            auto answer = QMessageBox::question(this,"Unsaved changes","Save configuration before closing?",
                QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel,QMessageBox::Cancel);
            if (answer == QMessageBox::Cancel || (answer == QMessageBox::Save && !save())) {
                event->ignore(); return;
            }
        }
        event->accept();
    }
};
#ifndef CONFIG_GUI_TEST
int main(int argc, char** argv) {
    ConfigEditor editor;
    int result = editor_init(&editor,argc,argv);
    if (result) return result < 0 ? 2 : 0;
    int qt_argc = 1;
    QApplication app(qt_argc,argv);
    int status;
    { Window window(&editor); window.show(); status = app.exec(); }
    editor_free(&editor); return status;
}
#endif
