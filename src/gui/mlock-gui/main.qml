import QtQuick 2.3
import QtQuick.Controls 1.2
import QtQuick.Window 2.0
import QtQuick.Layouts 1.1
import QtQuick.Dialogs 1.2
import de.andresimon 1.0

ApplicationWindow {
    id: window1
    visible: true

    color: "#49698d"
    title: "mlock GUI"
    minimumWidth: 500 + columns.x *2
    minimumHeight: columns.implicitHeight + columns.y *2

    maximumWidth: minimumWidth
    maximumHeight: minimumHeight

    x: Screen.width/2 - width/2
    y: Screen.height/2 - height/2

    MlockInterface {
        id: mlock
    }

    Rectangle {
        id: unlockScreen
        transitions: Transition {
            to: "hide"
            NumberAnimation { properties: "opacity"; easing.type: Easing.OutCirc; duration: 200  }
        }
        states: [
            State {
                name: "show"
                PropertyChanges {
                    target: unlockScreen
                    opacity:1
                    enabled: true
                }
            },
            State {
                name: "hide"
                PropertyChanges {
                    target: unlockScreen
                    opacity:0
                    enabled: false
                }
            }
        ]


        ColumnLayout{

            id: columns
            x: 25
            y: 25

            width: 500

            Label {
                text: "<font color=\"white\"><h1>Enter your email and passphrase</h1><br><b>mlock uses your email and passphrase to derive your <b>miniLock ID</b>.<br>Send your miniLock ID to others so they can encrypt files to you.<br>Encrypt files to friends using their miniLock IDs. <br><br>Your email is only used to derive your miniLock ID -<br> it remains completely secret and anonymous.<br></font>"
                Layout.fillWidth: true
            }

            TextField {
                id: txtMailAddress
                placeholderText: qsTr("E-Mail address")
                Layout.fillWidth: true
            }

            TextField {
                id: txtPassphrase
                echoMode: 2
                placeholderText: qsTr("Passphrase")
                Layout.fillWidth: true
            }

            Button {
                id: btnUnlock
                text: qsTr("Unlock")
                enabled: true
                Layout.fillWidth: true

                onClicked: {
                    btnUnlock.enabled    = false
                    txtMyId.text=mlock.unlock( txtPassphrase.text, txtMailAddress.text)
                    //btnUnlock.enabled    = true
                    btnNext.enabled = true
                }
            }

            TextField {
                id: txtMyId

                placeholderText: qsTr("My MiniLock ID")
                Layout.fillWidth: true
                readOnly: true

            }

            Button {
                id: btnNext
                text: qsTr("Process file")
                enabled: false
                Layout.fillWidth: true

                onClicked: {
                    unlockScreen.state = "hide"
                    selectFileScreen.state = "show"
                    btnSelFile.enabled=true
                }

            }
        }
    }

    Rectangle {

        id: selectFileScreen
        opacity:0
        enabled: false

        transitions: Transition {
            to: "show"
            NumberAnimation { properties: "opacity"; easing.type: Easing.InCirc; duration: 500  }
        }

        states: [
            State {
                name: "show"
                PropertyChanges {
                    target: selectFileScreen
                    opacity:1
                    enabled: true
                }
            },
            State {
                name: "hide"
                PropertyChanges {
                    target: selectFileScreen
                    opacity:0
                    enabled: false
                }
            }
        ]

        ColumnLayout{

            x: 25
            y: 25

            width: 500

            Label {
                text: "<font color=\"white\"><h1>Select a file</h1><br>Select a file to encrypt/decrypt.</font><br>"
                Layout.fillWidth: true
            }

            Button {
                id: btnSelFile
                text: qsTr("Select file")
                enabled: false
                Layout.fillWidth: true

                onClicked: {
                    fileDialog.open()
                }

            }

        }
    }


    Rectangle {

        id: encryptScreen
        opacity:0
        enabled: false

        transitions: Transition {
            to: "show"
            NumberAnimation { properties: "opacity"; easing.type: Easing.InCirc; duration: 500  }
        }

        states: [
            State {
                name: "show"
                PropertyChanges {
                    target: encryptScreen
                    opacity:1
                     enabled: true
                }
            },
            State {
                name: "hide"
                PropertyChanges {
                    target: encryptScreen
                    opacity:0
                     enabled: false
                }
            }
        ]

        ColumnLayout{

            x: 25
            y: 25

            width: 500

            Label {
                text: "<font color=\"white\"><h1>Encryption:</h1><br><b>Who is allowed to open this file?</b><br><br>Paste a miniLock ID for each person which needs access.</font>"
                Layout.fillWidth: true
            }

            TextField {
                id: txtRcpt1
                placeholderText: qsTr("Recipient miniLock ID #1")
                Layout.fillWidth: true
            }

            TextField {
                id: txtRcpt2
                placeholderText: qsTr("Recipient miniLock ID #2")
                Layout.fillWidth: true
            }

            TextField {
                id: txtRcpt3
                placeholderText: qsTr("Recipient miniLock ID #3")
                Layout.fillWidth: true
            }

            CheckBox {
                id: cbOmitMyId
                text: qsTr("<font color=\"white\">Omit my miniLock ID</font>")

            }

            Button {
                id: btnEncrypt

                text: qsTr("Encrypt file")
                enabled: true
                Layout.fillWidth: true

                onClicked: {
                    btnEncrypt.enabled= false
                    console.log("crypting...")
                    var retVal=mlock.encrypt( fileDialog.fileUrl, cbOmitMyId.checked, txtRcpt1.text, txtRcpt2.text, txtRcpt3.text)
                    if (retVal>0) {
                        show_error(retVal)
                    }
                    console.log("crypting done")
                    btnEncrypt.enabled= true
                }

            }

        }
    }


    //enum error_code { err_ok, err_failed, err_open, err_box,  err_file_open, err_file_read, err_file_write, err_hash, err_format, err_no_rcpt};
    function show_error(error) {
        switch (error){
        case 2:
            decErrorMsg.text="Could not decrypt the file."
            break
        case 3:
            decErrorMsg.text="Could not encrypt the file."
            break
        case 4:
            decErrorMsg.text="Could not open the file."
            break
        case 5:
            decErrorMsg.text="Could not read the file."
            break
        case 6:
            decErrorMsg.text="Could not write the file."
            break
        case 7:
            decErrorMsg.text="Could not calculate the hash of the file."
            break
        case 8:
            decErrorMsg.text="Illegal minilock file format."
            break
        case 9:
            decErrorMsg.text="No recipients defined."
            break
        }
        decErrorMsg.open()
    }

    FileDialog {
        id: fileDialog
        title: "Please choose a file"
        selectExisting: true
        selectMultiple: false
        modality:  "WindowModal"
        visible: false

        onAccepted: {
            var inFile = fileDialog.fileUrl.toString().substring(7)
            var patt = /minilock$/
            if (patt.test(inFile)){
                var retVal=mlock.decrypt( fileDialog.fileUrl)
                if (retVal>0) {
                    show_error(retVal)
                }
            } else {
                selectFileScreen.state = "hide"
                encryptScreen.state = "show"
            }
        }
        onRejected: {
            console.log("Canceled")
            //Qt.quit()
        }
        Component.onCompleted: visible = false
    }

    MessageDialog {
        id: decErrorMsg
        title: "Processing error"
        text: "Could not process the file."
        visible: false
        onAccepted: {
        }
        Component.onCompleted: visible = false
    }

}
