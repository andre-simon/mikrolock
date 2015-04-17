#include <QClipboard>
#include <QMessageBox>
#include <QFileDialog>
#include <QPixmap>
#include <QDesktopWidget>

#include "mlockmainwindow.h"
#include "ui_mlockmainwindow.h"

// static data items shared with threads
char* MlockMainWindow::c_rcpt_list[50]= {0};
unsigned int MlockMainWindow::num_rcpts=0;
uint8_t MlockMainWindow::b_my_sk[KEY_LEN] = {0};
uint8_t MlockMainWindow::b_my_pk[KEY_LEN + 1]= {0};
uint8_t MlockMainWindow::c_minilock_id[KEY_LEN * 2]= {0};
struct output_options MlockMainWindow::out_opts;


MlockMainWindow::MlockMainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MlockMainWindow)
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

    QWidget *central = new QWidget();

    scrollAreaLayout = new QVBoxLayout(central);
    ui->scrollRcptList->setWidget(central);
    ui->scrollRcptList->setWidgetResizable(true);

    for(int i=0;i<5;i++){
           QLineEdit* le =  new QLineEdit();
          // le->setFont(QFont("Courier New",8,1 ));
           scrollAreaLayout->addWidget(le);
    }

    this->setGeometry( QStyle::alignedRect(Qt::LeftToRight,Qt::AlignCenter, this->size(),
                                           qApp->desktop()->availableGeometry() ));
}

void MlockMainWindow::setInitialInputFile(QString file){
    inputFilename = file;
    statusBar()->showMessage(tr("Input file %1").arg(inputFilename));
}

void MlockMainWindow::on_txtPassPhrase_textChanged(){
    QString pp = ui->txtPassPhrase->text();
    ui->btnUnlock->setEnabled(!ui->txtMail->text().isEmpty()
                              && pp.length()>=40 && pp.count(QLatin1Char(' ')) > 3 );
}

void MlockMainWindow::on_btnUnlock_clicked(){

    this->setCursor(Qt::WaitCursor);
    std::string std_passphrase = ui->txtPassPhrase->text().toStdString();
    std::string std_salt  = ui->txtMail->text().toStdString();

    uint8_t b_cs[1];
    uint8_t b_passphrase_blake2[KEY_LEN] = {0};

    blake_2s_array((uint8_t*)std_passphrase.c_str(), std_passphrase.length(),
                   b_passphrase_blake2, KEY_LEN);

    int scrypt_retval= crypto_pwhash_scryptsalsa208sha256_ll(b_passphrase_blake2, KEY_LEN,
                                     (uint8_t*)std_salt.c_str(), std_salt.length(),
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
    } else {
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
              ui->txtDestDir->text().toStdString().c_str(),
              sizeof out_opts.c_override_out_name-1);

      if (!inputFilename.isEmpty()) {
          startFileProcessing(inputFilename.endsWith("minilock"));
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
    //le->setFont(QFont("Courier New",8,1 ));
    scrollAreaLayout->addWidget(le);

    if (scrollAreaLayout->count()==50) {
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

void MlockMainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    qDebug()<<"drag";
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

    std::string std_inFileName = inFileName.toStdString();

    int result= minilock_decode((uint8_t*) std_inFileName.c_str(),
                                MlockMainWindow::b_my_sk, MlockMainWindow::b_my_pk,
                                &MlockMainWindow::out_opts);
    emit resultReady(result);
}

void EncryptThread::run()  {

    std::string std_inFileName = inFileName.toStdString();
    int result= minilock_encode((uint8_t*) std_inFileName.c_str(), MlockMainWindow::c_minilock_id,
                                MlockMainWindow::b_my_sk,
                                MlockMainWindow::c_rcpt_list, MlockMainWindow::num_rcpts,
                                &MlockMainWindow::out_opts);
    emit resultReady(result);
}

void UpdateProgressBarThread::run() {

   int percentage=0;
   while (percentage<100){
       percentage = (int)MlockMainWindow::out_opts.crypto_progress/2 + MlockMainWindow::out_opts.hash_progress/2;
       bar->setValue(percentage);
       QThread::msleep(200);
    }
}
