/*
mlock reads and writes encrypted files in the minilock format

Copyright (C) 2015 Andre Simon

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <QClipboard>
#include <QMessageBox>
#include <QFileDialog>
#include <QPixmap>
#include <QDesktopWidget>
#include <QDesktopServices>

#include <QFileInfo>

#include "mlockmainwindow.h"
#include "ui_mlockmainwindow.h"

#include "showmanualdialog.h"

// static data items shared with threads
char* MlockMainWindow::c_rcpt_list[MAX_RCPT]= {0};
unsigned int MlockMainWindow::num_rcpts=0;
uint8_t MlockMainWindow::b_my_sk[KEY_LEN] = {0};
uint8_t MlockMainWindow::b_my_pk[KEY_LEN + 1]= {0};
uint8_t MlockMainWindow::c_minilock_id[KEY_LEN * 2]= {0};
struct output_options MlockMainWindow::out_opts;
bool MlockMainWindow::forceThreadStop=false;

MlockMainWindow::MlockMainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MlockMainWindow),
    startedWithFilArg(false)
{
    ui->setupUi(this);

    ui->stackedWidget->setCurrentIndex(0);
    ui->lblCurrentAction->setVisible(false);
    ui->progressBar->setVisible(false);

    memset(out_opts.c_final_out_name, 0, sizeof out_opts.c_final_out_name);
    memset(out_opts.c_override_out_name, 0, sizeof out_opts.c_override_out_name);
    out_opts.override_out_name_as_dir=1;
    out_opts.task_mode=0;
    out_opts.crypto_progress=0.0;
    out_opts.hash_progress=0.0;
    out_opts.silent_mode=1;
    out_opts.random_outname=0;

    QWidget *central = new QWidget();

    scrollAreaLayout = new QVBoxLayout(central);
    ui->scrollRcptList->setWidget(central);
    ui->scrollRcptList->setWidgetResizable(true);

    for(int i=0;i<5;i++){
           QLineEdit* le =  new QLineEdit();
           scrollAreaLayout->addWidget(le);
    }

    this->setGeometry( QStyle::alignedRect(Qt::LeftToRight,Qt::AlignCenter, this->size(),
                                           qApp->desktop()->availableGeometry() ));


}

void MlockMainWindow::setInitialInputFile(QString file){
    inputFilename = file;
    startedWithFilArg=true;
}

void MlockMainWindow::on_txtPassPhrase_textChanged(){
    QString pp = ui->txtPassPhrase->text();

    ui->lblSecIcon->setEnabled(!pp.isEmpty());

    if (pp.length() < 20){
        ui->lblSecIcon->setPixmap(QPixmap (":/Status-security-low-icon.png"));
        ui->btnUnlock->setEnabled(false);
        return;
    }
    if (pp.length() > 40){
        ui->lblSecIcon->setPixmap(QPixmap (":/Status-security-high-icon.png"));
        ui->btnUnlock->setEnabled(!ui->txtMail->text().isEmpty() );
        return;
    }

    ui->lblSecIcon->setPixmap(QPixmap (":/Status-security-medium-icon.png"));

    pp=pp.trimmed();
    int wordCount=0;
    for (int i=1;i<pp.length();i++){
        if (pp[i]==' ' && pp[i-1]!=' ')
            wordCount++;
    }

    ui->btnUnlock->setEnabled(!ui->txtMail->text().isEmpty()
                              && wordCount> 3 );
}

void MlockMainWindow::on_btnUnlock_clicked(){

    this->setCursor(Qt::WaitCursor);
    QByteArray passphrase = ui->txtPassPhrase->text().toUtf8();
    QByteArray salt  = ui->txtMail->text().toUtf8();

    uint8_t b_cs[1];
    uint8_t b_passphrase_blake2[KEY_LEN] = {0};

    blake_2s_array((uint8_t*)passphrase.data(), passphrase.length(),
                   b_passphrase_blake2, KEY_LEN);

    int scrypt_retval= crypto_pwhash_scryptsalsa208sha256_ll(b_passphrase_blake2, KEY_LEN,
                                     (uint8_t*)salt.data(), salt.length(),
                                     131072, 8, 1,
                                     b_my_sk, sizeof b_my_sk);
    if (scrypt_retval) {
        QMessageBox::critical(this, tr("Scrypt error"), tr("Key derivation failed"));
        return;
    }

    crypto_scalarmult_base(b_my_pk, b_my_sk);

    blake_2s_array(b_my_pk, KEY_LEN , b_cs, sizeof b_cs);
    b_my_pk[KEY_LEN] = b_cs[0];

    base58_encode((unsigned char *)c_minilock_id, b_my_pk, KEY_LEN + 1);

    ui->lblMyId->setText( QString((const char*)c_minilock_id));
    ui->btnCopyId->setEnabled(true);
    ui->stackedWidget->setCurrentIndex(1);
    ui->lbGoPreviousScreen->setEnabled(true);
    this->setCursor(Qt::ArrowCursor);
}

void MlockMainWindow::on_btnCopyId_clicked(){
    QClipboard *clipboard = QApplication::clipboard();
    if (clipboard) {
        clipboard->setText(ui->lblMyId->text());
    }
}

void MlockMainWindow::initProgressDisplay(bool isEncryptMode)
{
    statusBar()->showMessage(tr("%1 file %2...").arg(
                                 (ui->stackedWidget->currentIndex()==1)?
                                     tr("Decrypting"): tr("Encrypting")).arg(inputFilename));
    this->setCursor(Qt::WaitCursor);
    timer.restart();
    QPixmap actionPix( isEncryptMode ? ":/Actions-document-encrypt-icon.png": ":/Actions-document-decrypt-icon.png");
    ui->lblCurrentAction->setPixmap(actionPix);
    ui->lblCurrentAction->setVisible(true);
    ui->progressBar->setValue(0);
    ui->progressBar->setVisible(true);
    ui->btnEncrypt->setEnabled(false);
    out_opts.crypto_progress=0.0;
    out_opts.hash_progress=0.0;
}

void MlockMainWindow::decrypt(){

    initProgressDisplay(false);

    UpdateProgressBarThread *progressUpdate = new UpdateProgressBarThread(ui->progressBar);
    connect(progressUpdate, &UpdateProgressBarThread::finished, progressUpdate, &QObject::deleteLater);
    progressUpdate->start();

    DecryptThread *workerThread = new DecryptThread(inputFilename);
    connect(workerThread, &DecryptThread::resultReady, this, &MlockMainWindow::handleResults);
    connect(workerThread, &DecryptThread::finished, workerThread, &QObject::deleteLater);
    workerThread->start();
}

void MlockMainWindow::encrypt() {

    freeMem();

    if (!ui->cbOmitId->isChecked()){
        c_rcpt_list[num_rcpts] = (char*)malloc(strlen((char*)c_minilock_id)+1);
        snprintf(c_rcpt_list[num_rcpts], strlen((char*)c_minilock_id)+1, "%s",(char*)c_minilock_id);
        num_rcpts++;
    }

    QString rcptId;
    QLineEdit *leCurrentId;
    for (int i=0; i<scrollAreaLayout->count(); i++){
        leCurrentId = dynamic_cast<QLineEdit*>(scrollAreaLayout->itemAt(i)->widget());
        rcptId = leCurrentId->text().trimmed();
        if (!rcptId.isEmpty()){

            if (!checkMiniLockID(rcptId)){
                QMessageBox::critical(this, tr("Bad miniLock ID"), tr("The ID %1 is invalid.").arg(rcptId));
                leCurrentId->selectAll();
                leCurrentId->setFocus();
                return;
            }

            c_rcpt_list[num_rcpts] =  (char*)malloc(rcptId.size()+1);
            snprintf(c_rcpt_list[num_rcpts], rcptId.size()+1, "%s",(char*)rcptId.toStdString().c_str());
            num_rcpts++;
        }
    }

    if (num_rcpts==0){
        QMessageBox::warning(this, tr("No recipients"), tr("You need to define some recipient IDs."));
        return;
    }

    initProgressDisplay(true);

    out_opts.random_outname =  ui->cbRandomFileName->isChecked();

    UpdateProgressBarThread *progressUpdate = new UpdateProgressBarThread(ui->progressBar);
    connect(progressUpdate, &UpdateProgressBarThread::finished, progressUpdate, &QObject::deleteLater);
    progressUpdate->start();

    EncryptThread *workerThread = new EncryptThread(inputFilename);
    connect(workerThread, &EncryptThread::resultReady, this, &MlockMainWindow::handleResults);
    connect(workerThread, &EncryptThread::finished, workerThread, &QObject::deleteLater);

    workerThread->start();
}


void MlockMainWindow::freeMem(bool exitApp){
    if (num_rcpts>0){
        while (num_rcpts--  ) {
            free(c_rcpt_list[num_rcpts]);
        }
    }
    num_rcpts=0;

    if (exitApp){
        sodium_memzero( b_my_sk, sizeof b_my_sk);
    }
}

void MlockMainWindow::handleResults(int result){

    if (result==0){
        statusBar()->showMessage(tr("%1 file %2 in %3s").arg(
                                     (ui->stackedWidget->currentIndex()==1) ?
                                         tr("Decrypted"): tr("Encrypted")).arg(inputFilename).arg(timer.elapsed()/1000));
        QPixmap actionPix(":/Actions-dialog-ok-apply-icon.png");
        ui->lblCurrentAction->setPixmap(actionPix);
        ui->btnSelInputFile->setEnabled(true); //if mlock-gui was called with file arg...
    } else {
        forceThreadStop=true;

        QPixmap actionPix(":/Actions-process-stop-icon.png");
        ui->lblCurrentAction->setPixmap(actionPix);

        switch((enum error_code)result){

        case err_failed:
            QMessageBox::critical(this, tr("Error") , tr("Unknown error."));
            break;

        case err_open:
            QMessageBox::critical(this, tr("Error") , tr("Could not decrypt the file."));
            break;

        case err_box:
            QMessageBox::critical(this, tr("Error") , tr("Could not encrypt the file."));
            break;

        case err_file_open:
            QMessageBox::critical(this, tr("Error") , tr("Could not open the file."));
            break;

        case err_file_read:
            QMessageBox::critical(this, tr("Error") , tr("Could not read the file."));
            break;

        case err_file_write:
            QMessageBox::critical(this, tr("Error") , tr("Could not write the file."));
            break;

        case err_hash:
            QMessageBox::critical(this, tr("Error") , tr("Could not calculate the hash of the file."));
            break;

        case err_format:
            QMessageBox::critical(this, tr("Error") , tr("Illegal minilock file format."));
            break;

        case err_no_rcpt:
            QMessageBox::critical(this, tr("Error") , tr("No recipients defined."));
            break;

        case err_not_allowed:
            QMessageBox::critical(this, tr("Error") , tr("You are not allowed to decrypt the file."));
            break;

        case err_file_empty:
            QMessageBox::critical(this, tr("Error") , tr("Empty input file."));
            break;

        case err_file_exists:
            QMessageBox::critical(this, tr("Error") , tr("Output file exists:\n%1").arg(QString((const char *)out_opts.c_final_out_name)).toLocal8Bit());
            break;

        default:
            QMessageBox::critical(this, tr("Error") , tr("Undefined error."));
            break;
        }

    }
    this->setCursor(Qt::ArrowCursor);
    ui->btnEncrypt->setEnabled(true);
}

bool MlockMainWindow::checkMiniLockID(QString id)
{
    std::string std_id= id.toStdString();
    uint8_t b_rcpt_pk[KEY_LEN + 1]= {0};
    uint8_t b_cs[1];

    base58_decode(b_rcpt_pk, (const unsigned char*)std_id.c_str());
    blake_2s_array(b_rcpt_pk, KEY_LEN , b_cs, sizeof b_cs);
    return  b_cs[0]==b_rcpt_pk[KEY_LEN];
}

void MlockMainWindow::on_lbGoPreviousScreen_clicked(){

    if (ui->stackedWidget->currentIndex()>0)
        ui->stackedWidget->setCurrentIndex(ui->stackedWidget->currentIndex()-1);

    ui->lbGoPreviousScreen->setEnabled(ui->stackedWidget->currentIndex()>0);
}

void MlockMainWindow::on_btnSelectDestDir_clicked()
{
    QFileDialog dialog(this, tr("Select destination directory"), "");
    dialog.setFileMode(QFileDialog::Directory);
    if (dialog.exec() && !dialog.selectedFiles().empty()) {
      ui->txtDestDir->setText(QDir::toNativeSeparators(dialog.selectedFiles().at(0)));

      strncpy((char*)out_opts.c_override_out_name,
              ui->txtDestDir->text().toLocal8Bit().data(),
              sizeof out_opts.c_override_out_name-1);

      if (startedWithFilArg && !inputFilename.isEmpty()) {
          startFileProcessing(inputFilename.endsWith("minilock"));
          startedWithFilArg=false;
        } else {
          ui->btnSelInputFile->setEnabled(true);
      }
    }
}

void MlockMainWindow::on_btnSelInputFile_clicked()
{
    inputFilename = QFileDialog::getOpenFileName(this, tr("Select the input file"), "", "*.*");
    startFileProcessing();
}


void MlockMainWindow::startFileProcessing(bool promptDecrypt)
{
    if (!inputFilename.isEmpty()) {

        if (promptDecrypt &&  QMessageBox::question(this, tr("Decrypt given file"),
                                                    tr("Decrypt %1?").arg(inputFilename),
                                                    QMessageBox::Yes|QMessageBox::No)== QMessageBox::No)
            return;

        if (inputFilename.endsWith("minilock"))
            decrypt();
        else
            ui->stackedWidget->setCurrentIndex(2);
    }
}

void MlockMainWindow::dropEvent(QDropEvent* event)
{

    if (ui->txtDestDir->text().isEmpty()) return;

    QList<QUrl> urls = event->mimeData()->urls();
       if (urls.isEmpty())
           return;

       QString fileName = urls.first().toLocalFile();
       if (!fileName.isEmpty())
           inputFilename=fileName;

       statusBar()->showMessage(tr("Input file %1").arg(inputFilename));
       startFileProcessing();
}

void MlockMainWindow::on_btnAddRcpt_clicked()
{
    QLineEdit* le =  new QLineEdit();
    scrollAreaLayout->addWidget(le);
    if (scrollAreaLayout->count()==MAX_RCPT) {
        ui->btnAddRcpt->setEnabled(false);
    }
}

void MlockMainWindow::on_btnEncrypt_clicked()
{
    encrypt();
}

void MlockMainWindow::on_txtDestDir_textChanged()
{
    if (!ui->txtDestDir->text().endsWith(QDir::separator())) {
       ui->txtDestDir->setText(ui->txtDestDir->text() +  QDir::separator());
    }
}

void MlockMainWindow::on_txtMail_textChanged()
{
    ui->txtPassPhrase->clear();
}

void MlockMainWindow::on_actionAbout_mlock_triggered()
{
    QMessageBox::about( this, "About mlock",
                        QString("mlock reads and writes encrypted minilock files.\n\n"
                        "mlock GUI %1\n"
                        "(C) 2015 Andre Simon <andre.simon1 at gmx.de>\n\n"
                        "Minilock file format specification:\n"
                        "https://minilock.io\n\n"
                        "Built with Qt version %2\n\n"
                        "Icons are based on the KDE Oxygen icon theme\n\n"
                        "Released under the terms of the GNU GPL license.\n\n"
                        ).arg(MLOCK_VERSION).arg(QString(qVersion ())) );
}

void MlockMainWindow::on_action_Manual_triggered(){

     ShowManualDialog dialog;
     QString l10nManualUri  = ":/manual/manual_"+QLocale::system().name()+".html";

     if (QFileInfo::exists(l10nManualUri))
         dialog.setHTMLSource(l10nManualUri);
    else
         dialog.setHTMLSource(":/manual/manual_en_EN.html");

     dialog.exec();
}

void MlockMainWindow::on_btnClearRecipients_clicked()
{
    QLineEdit *leCurrentId;
    for (int i=0; i<scrollAreaLayout->count(); i++){
        leCurrentId = dynamic_cast<QLineEdit*>(scrollAreaLayout->itemAt(i)->widget());
        leCurrentId->setText("");
    }
}

void MlockMainWindow::on_btnOpenFileList_clicked()
{
    QString listFilename = QFileDialog::getOpenFileName(this, tr("Select the recipient list file"), "", "*");

    if (!listFilename.isEmpty()){
        QFile f(listFilename);

        if (f.open(QIODevice::ReadOnly))
        {
            on_btnClearRecipients_clicked();

            QString data = f.readAll();
            QStringList vals = data.split('\n');

            QRegExp delimRE("[\\,\\;\\|\\-\\/]");

            for (int i=0;i<vals.count() && i< MAX_RCPT;i++){

                if (i> scrollAreaLayout->count()-1){
                    QLineEdit* le =  new QLineEdit();
                    scrollAreaLayout->addWidget(le);
                }

                QLineEdit *leCurrentId = dynamic_cast<QLineEdit*>(scrollAreaLayout->itemAt(i)->widget());

                QString line(vals[i]);
                int delimPos = line.indexOf(delimRE);

                if (delimPos<0){
                    leCurrentId->setText(line.trimmed());
                } else {
                    leCurrentId->setText(line.mid(0,delimPos).trimmed());
                    leCurrentId->setToolTip(line.mid(delimPos+1).replace(delimRE, ""));
                }
            }

            f.close();

            if (scrollAreaLayout->count()==MAX_RCPT) {
                ui->btnAddRcpt->setEnabled(false);
            }
        }
    }
}

void MlockMainWindow::on_stackedWidget_currentChanged(int idx)
{
    ui->progressBar->setVisible(false);
    ui->lblCurrentAction->setVisible(false);
    switch(idx){
    case 0:
        if (startedWithFilArg)
            statusBar()->showMessage(tr("Input file %1").arg(inputFilename));
        else
            statusBar()->showMessage(tr("Enter your mail adress and passphrase"));
        break;
    case 1:
        statusBar()->showMessage(tr("Set input and output parameters"));
        break;
    case 2:
        statusBar()->showMessage(tr("Set encryption options for %1").arg(inputFilename));
        break;
     default:
        statusBar()->showMessage("");
        break;
    }
    this->setAcceptDrops(idx==1);
}

void MlockMainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasFormat("text/uri-list"))
        event->acceptProposedAction();
}

MlockMainWindow::~MlockMainWindow()
{
    freeMem(true);
    delete ui;
}

/// Threads

void DecryptThread::run() {
    int result= minilock_decode((uint8_t*) inFileName.toLocal8Bit().data(),
                                MlockMainWindow::b_my_sk, MlockMainWindow::b_my_pk,
                                &MlockMainWindow::out_opts);
    emit resultReady(result);
}

void EncryptThread::run()  {

    /*
    QString encFileName(inFileName);


    if (randomizeOutfile){
        uint8_t  b_file_rnd[6]= {0};
        char  c_b58_file_rnd[12]= {0};
        randombytes_buf(b_file_rnd, sizeof b_file_rnd);
        base58_encode((unsigned char *)c_b58_file_rnd,(const unsigned char *)b_file_rnd, sizeof b_file_rnd);
        encFileName.sprintf("%s.minilock", c_b58_file_rnd);
    }*/

    int result= minilock_encode((uint8_t*) inFileName.toLocal8Bit().data(), MlockMainWindow::c_minilock_id,
                                MlockMainWindow::b_my_sk,
                                MlockMainWindow::c_rcpt_list, MlockMainWindow::num_rcpts,
                                &MlockMainWindow::out_opts);
    emit resultReady(result);
}

void UpdateProgressBarThread::run() {

   int percentage=0;
   MlockMainWindow::forceThreadStop=false;

   while (percentage<100 &&!MlockMainWindow::forceThreadStop){
       percentage = (int)MlockMainWindow::out_opts.crypto_progress/2 + MlockMainWindow::out_opts.hash_progress/2;
       bar->setValue(percentage);
       QThread::msleep(200);
   }
   if (MlockMainWindow::forceThreadStop)
       bar->setValue(0);
}
