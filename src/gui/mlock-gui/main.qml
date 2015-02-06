import QtQuick 2.3
import QtQuick.Controls 1.2
import QtQuick.Window 2.0
import QtQuick.Layouts 1.1
import de.andresimon 1.0

ApplicationWindow {
    id: window1
    visible: true
    width: 600
    height: 500
    color: "#49698d"
    title: "mlock UI"
    //minimumWidth: columns.implicitWidth + columns.x *2
    //minimumHeight: columns.implicitHeight + columns.y *2

    MlockInterface {
         id: mlock
      }

  //  ColumnLayout{

    //    id: columns
      //  x: 15
        //y: 15

        TextArea {
            id: textArea1
            x: 20
            y: 24
            width: 240
            height: 53
            text: "Description"
            readOnly: true

        }

        TextField {
            id: txtMailAddress
            x: 27
            y: 143
            width: 233
            height: 22
            placeholderText: qsTr("E-Mail address")
            Layout.fillWidth: true
        }

        TextField {
            id: txtPassphrase
            x: 27
            y: 182
            width: 233
            height: 22
            echoMode: 2
            placeholderText: qsTr("Passphrase")
            Layout.fillWidth: true
        }

        Button {
            id: btnUnlock
            x: 27
            y: 226
            text: qsTr("Unlock")
            enabled: true
            Layout.fillWidth: true

            onClicked: {
                        btnUnlock.enabled    = false

                        console.log("unlocking...")
                        txtMyId.text=mlock.unlock( txtPassphrase.text, txtMailAddress.text)
                console.log("unlocking done")
                btnUnlock.enabled    = true
                        btnNext.enabled = true

                    }
        }

        TextField {
            id: txtMyId
            x: 24
            y: 254

            width: 233
            height: 22

            placeholderText: qsTr("My MiniLock ID")
            Layout.fillWidth: true
            readOnly: true
        }

        Button {
            id: btnNext
            x: 39
            y: 310
            width: 69
            height: 70
            text: qsTr("Process file")
            enabled: false
            Layout.fillWidth: true

            onClicked: {

                    }
        }
//    }
    //  x: Screen.width/2 - width/2
    //  y: Screen.height/2 - height/2
}
