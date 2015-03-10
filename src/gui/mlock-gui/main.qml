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
    title: "mlock GUI 0.5"
    minimumWidth: 500 + columns.x *2
    minimumHeight: columns.implicitHeight + columns.y *2

    maximumWidth: minimumWidth
    maximumHeight: minimumHeight

    x: Screen.width/2 - width/2
    y: Screen.height/2 - height/2

    property bool isBusy: false

    onClosing:  {
        mlock.freeMem()
    }

    MlockInterface {
        id: mlock
    }

    BusyIndicator {
        id: busyIndication
        anchors.centerIn: parent
        running: false
        z: 100
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
            x: 50
            y: 50

            width: 500

            Label {
                text: "<font color=\"white\"><h1>"+qsTr("Enter your email and passphrase")+"</h1><br><b>"+qsTr("mlock uses your email and passphrase to derive your <b>miniLock ID</b>.")+"<br>"+qsTr("Send your miniLock ID to others so they can encrypt files to you.<br>Encrypt files to friends using their miniLock IDs. <br><br>Your email is only used to derive your miniLock ID -<br> it remains completely secret and anonymous.")+"<br></font>"
                Layout.fillWidth: true
            }

            TextField {
                id: txtMailAddress
                placeholderText: qsTr("E-Mail address")
                Layout.fillWidth: true
                onTextChanged: { btnUnlock.enabled=true }
            }

            TextField {
                id: txtPassphrase
                echoMode: 2
                placeholderText: qsTr("Passphrase")
                Layout.fillWidth: true
                onTextChanged: { btnUnlock.enabled=true }
            }

            Button {
                id: btnUnlock
                text: qsTr("Unlock")
                enabled: true
                Layout.fillWidth: true

                onClicked: {

                    if (txtPassphrase.text.length<40){
                        inputErrorMsg.text = qsTr("The passphrase must consist of several random words")
                        inputErrorMsg.open()
                        txtPassphrase.forceActiveFocus()
                        return
                    }
                    if (txtMailAddress.text.length==0){
                        inputErrorMsg.text = qsTr("The mail address must be set")
                        inputErrorMsg.open()
                        txtMailAddress.forceActiveFocus()
                        return
                    }

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
                text: qsTr("<b>Encrypt or decrypt file</b>")
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

            x: 50
            y: 50

            width: 500


            Label {
                text: "<font color=\"white\"><h1>"+qsTr("Select the destination directory")+"</h1></font><br>"
                Layout.fillWidth: true
            }

            Button {
                id: btnSelDestFile
                text: qsTr("Save file in...")
                enabled: true
                Layout.fillWidth: true

                onClicked: {
                    destFileDialog.open()
                }
            }

            TextField {
                id: txtDestFile

                placeholderText: qsTr("Destination directory")
                Layout.fillWidth: true
                readOnly: false
            }

            Label {
                text: "<br><font color=\"white\"><h1>"+qsTr("Select an input file")+"</h1><br>"+qsTr("A miniLock file will be automatically decrypted.<br>Any other file will be encrypted.")+"</font><br>"
                Layout.fillWidth: true
            }

            Button {

                id: btnSelFile
                text: qsTr("Select a file to encrypt or decrypt.")
                enabled: false
                Layout.fillWidth: true

                onClicked: {
                    //todo: bei decrypt muesste man ausgabeverz. angeben koennen
                    // encrypt nimmt als default eingabepfad + .minilock
                    if (txtDestFile.text.length==0){
                        inputErrorMsg.text = qsTr("The destination file must be set")
                        inputErrorMsg.open()
                        txtDestFile.forceActiveFocus()
                        return
                    }

                    fileDialog.open()
                }

            }

            Label {
                id: lblWorking1
                text:  "<br><font color=\"yellow\"><h2>---WORKING---</h2></font>"
                opacity: 0
                Layout.fillWidth: true
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

            x: 50
            y: 50

            width: 500

            Label {
                text: "<font color=\"white\"><h1>"+qsTr("Encryption")+"</h1><br><b>"+qsTr("Who is allowed to open this file?")+"</b><br><br>"+qsTr("Paste a miniLock ID for each person which needs access.")+"</font>"
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
                text: qsTr("<font color=\"white\">"+qsTr("Omit my miniLock ID (you won't be able to decrypt the file)")+"</font>")

            }

            Button {
                id: btnEncrypt

                text: qsTr("Encrypt file")
                enabled: true
                Layout.fillWidth: true

                onClicked: {

                    if (!mlock.checkMiniLockID(txtRcpt1.text)  ||  !mlock.checkMiniLockID(txtRcpt2.text) || !mlock.checkMiniLockID(txtRcpt3.text)){
                        inputErrorMsg.text = qsTr("A miniLock ID is invalid")
                        inputErrorMsg.open()
                        return
                    }
                    console.log("encrypt...")
                    busyIndication.running=true
busyIndication.visible=true
                    btnEncrypt.enabled= false
                    lblWorking2.opacity= 1
                   lblWorking2.visible= true
                    var retVal=mlock.encrypt( fileDialog.fileUrl, txtDestFile.text, cbOmitMyId.checked, txtRcpt1.text, txtRcpt2.text, txtRcpt3.text)
                    if (retVal>0) {
                        show_error(retVal)
                        lblWorking2.opacity=0
                    } else {
                        lblWorking2.text = "<br><font color=\"yellow\"><h2>*** SUCCESS ***</h2></font>"
                    }
                    btnEncrypt.enabled= true
busyIndication.visible=false
                    busyIndication.running=false
                }

            }

            Label {
                id: lblWorking2
                text: "<br><font color=\"yellow\"><h2>---WORKING---</h2></font>"
                opacity: 0
                Layout.fillWidth: true

            }

        }
    }


    //enum error_code { err_ok, err_failed, err_open, err_box,  err_file_open, err_file_read, err_file_write, err_hash, err_format, err_no_rcpt};
    function show_error(error) {
        switch (error){
        case 2:
            decErrorMsg.text=qsTr("Could not decrypt the file.")
            break
        case 3:
            decErrorMsg.text=qsTr("Could not encrypt the file.")
            break
        case 4:
            decErrorMsg.text=qsTr("Could not open the file.")
            break
        case 5:
            decErrorMsg.text=qsTr("Could not read the file.")
            break
        case 6:
            decErrorMsg.text=qsTr("Could not write the file.")
            break
        case 7:
            decErrorMsg.text=qsTr("Could not calculate the hash of the file.")
            break
        case 8:
            decErrorMsg.text=qsTr("Illegal minilock file format.")
            break
        case 9:
            decErrorMsg.text=qsTr("No recipients defined.")
            break
        }
        decErrorMsg.open()
    }




    FileDialog {
        id: fileDialog
        title: qsTr("Please choose a file")
        selectExisting: true
        selectMultiple: false
        modality:  "WindowModal"
        visible: false


        onAccepted: {
            var inFile = mlock.localFilePath( fileDialog.fileUrl.toString())
            var patt = /minilock$/
            if (patt.test(inFile)){
                btnSelFile.enabled=false
                isBusy=true
                lblWorking1.opacity = 1
                var retVal=mlock.decrypt( fileDialog.fileUrl, txtDestFile.text)
                if (retVal>0) {
                    show_error(retVal)
                    lblWorking1.opacity=0
                } else {
                    lblWorking1.text = "<br><font color=\"yellow\"><h2>*** SUCCESS ***</h2></font>"
                }
                btnSelFile.enabled=true
                isBusy=false
            } else {
                selectFileScreen.state = "hide"
                encryptScreen.state = "show"
            }
        }

        Component.onCompleted: visible = false
    }

    FileDialog {
        id: destFileDialog
        title: qsTr("Please choose the destination directory")
        selectExisting: true
        selectFolder: true
        selectMultiple: false
        modality:  "WindowModal"
        visible: false

        onAccepted: {
            txtDestFile.text =  mlock.localFilePath( destFileDialog.fileUrl.toString())+"/"
        }

    }

    MessageDialog {
        id: decErrorMsg
        title: qsTr("Processing error")
        text: qsTr("Could not process the file.")
        visible: false
    }


    MessageDialog {
        id: inputErrorMsg
        title: qsTr("Input validation error")
        text: qsTr("Invalid input.")
        visible: false
    }
}
