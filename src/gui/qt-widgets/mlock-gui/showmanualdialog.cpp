#include "qdebug.h"
#include "showmanualdialog.h"
#include "ui_showmanualdialog.h"

ShowManualDialog::ShowManualDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ShowManualDialog)
{
    ui->setupUi(this);
}

ShowManualDialog::~ShowManualDialog()
{
    delete ui;
}

void ShowManualDialog::setHTMLSource(const QString& source){
    ui->textBrowser->setSource(QUrl("qrc"+source));
}
