#ifndef SHOWMANUALDIALOG_H
#define SHOWMANUALDIALOG_H

#include <QDialog>

namespace Ui {
class ShowManualDialog;
}

class ShowManualDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ShowManualDialog(QWidget *parent = 0);
    ~ShowManualDialog();

    void setHTMLSource(const QString& source);

private:
    Ui::ShowManualDialog *ui;
};

#endif // SHOWMANUALDIALOG_H
