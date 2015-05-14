#ifndef MLOCKMAINWINDOW_H
#define MLOCKMAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QDir>
#include <QDebug>
#include <QDropEvent>
#include <QDragEnterEvent>
#include <QMimeData>
#include <QProgressBar>
#include <QTime>
#include <QLineEdit>
#include <QVBoxLayout>
#include <string.h>

extern "C" {
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include <sodium/randombytes.h>
#include "utils.h"
#include "minilock.h"
}

namespace Ui {
class MlockMainWindow;
}

class MlockMainWindow : public QMainWindow
{
    Q_OBJECT

public:

    static char* c_rcpt_list[50];
    static unsigned int num_rcpts;
    static uint8_t b_my_sk[KEY_LEN] ;
    static uint8_t b_my_pk[KEY_LEN + 1];
    static uint8_t c_minilock_id[KEY_LEN * 2];

    static struct output_options out_opts;

    static bool forceThreadStop;


    explicit MlockMainWindow(QWidget *parent = 0);
    ~MlockMainWindow();

    void setInitialInputFile(QString);

private:
    Ui::MlockMainWindow *ui;

    bool startedWithFilArg;


    void dropEvent(QDropEvent* event);
    void dragEnterEvent(QDragEnterEvent *event);

    bool checkMiniLockID(QString);
    QString unlock(QString, QString);
    QString localFilePath(QString);
    void decrypt();
    void encrypt();
    void freeMem(bool exitApp=false);
    void startFileProcessing(bool promptDecrypt=false);
    void initProgressDisplay(bool);

    QString inputFilename;
    QTime timer;
    QVBoxLayout *scrollAreaLayout;

    QRegExp mailRE;

private slots:
    void on_txtPassPhrase_textChanged();
    void on_btnUnlock_clicked();
    void on_btnCopyId_clicked();
    void on_lbGoPreviousScreen_clicked();
    void on_btnSelectDestDir_clicked();

    void on_btnSelInputFile_clicked();
    void on_btnAddRcpt_clicked();
    void on_btnEncrypt_clicked();
    void on_txtDestDir_textChanged();
    void on_txtMail_textChanged();
    void on_actionAbout_mlock_triggered();
    void on_action_Manual_triggered();
    void on_btnClearRecipients_clicked();
    void on_btnOpenFileList_clicked();
    void on_btnBrowseDestDir_clicked();

    void on_stackedWidget_currentChanged(int idx);

  public slots:
    void handleResults(int);

};

class DecryptThread : public QThread
{
    QString inFileName;

public:
    DecryptThread(const QString  &fileName){
       inFileName = fileName;
    }

    Q_OBJECT
    void run() Q_DECL_OVERRIDE ;

signals:
    void resultReady(const int s);
};


class EncryptThread : public QThread
{
   QString inFileName;

public:
    EncryptThread(const QString  &fileName){
       inFileName = fileName;
    }

    Q_OBJECT
    void run() Q_DECL_OVERRIDE ;

signals:
    void resultReady(const int s);
};

class UpdateProgressBarThread : public QThread
{
    QProgressBar *bar;

public:
    UpdateProgressBarThread(QProgressBar *b){
       bar=b;
    }

    Q_OBJECT
    void run() Q_DECL_OVERRIDE ;
};


#endif // MLOCKMAINWINDOW_H
