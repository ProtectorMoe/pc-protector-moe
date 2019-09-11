# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Frame_user_login.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Frame_user_login(object):
    def setupUi(self, Frame_user_login):
        Frame_user_login.setObjectName("Frame_user_login")
        Frame_user_login.resize(180, 153)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon/icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Frame_user_login.setWindowIcon(icon)
        self.ed_username = QtWidgets.QLineEdit(Frame_user_login)
        self.ed_username.setGeometry(QtCore.QRect(30, 30, 141, 21))
        self.ed_username.setObjectName("ed_username")
        self.ed_password = QtWidgets.QLineEdit(Frame_user_login)
        self.ed_password.setGeometry(QtCore.QRect(30, 60, 141, 21))
        self.ed_password.setObjectName("ed_password")
        self.label = QtWidgets.QLabel(Frame_user_login)
        self.label.setGeometry(QtCore.QRect(10, 30, 16, 21))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("icon/mine.png"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Frame_user_login)
        self.label_2.setGeometry(QtCore.QRect(10, 60, 16, 21))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap("icon/lock.png"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")
        self.cb_server = QtWidgets.QComboBox(Frame_user_login)
        self.cb_server.setGeometry(QtCore.QRect(30, 90, 141, 22))
        self.cb_server.setObjectName("cb_server")
        self.cb_server.addItem("")
        self.cb_server.addItem("")
        self.cb_server.addItem("")
        self.cb_server.addItem("")
        self.cb_server.addItem("")
        self.label_4 = QtWidgets.QLabel(Frame_user_login)
        self.label_4.setGeometry(QtCore.QRect(10, 10, 161, 16))
        self.label_4.setObjectName("label_4")
        self.label_3 = QtWidgets.QLabel(Frame_user_login)
        self.label_3.setGeometry(QtCore.QRect(10, 90, 16, 21))
        self.label_3.setText("")
        self.label_3.setPixmap(QtGui.QPixmap("icon/server.png"))
        self.label_3.setScaledContents(True)
        self.label_3.setObjectName("label_3")
        self.bt_close = QtWidgets.QPushButton(Frame_user_login)
        self.bt_close.setGeometry(QtCore.QRect(10, 120, 161, 23))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("icon/login.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.bt_close.setIcon(icon1)
        self.bt_close.setObjectName("bt_close")

        self.retranslateUi(Frame_user_login)
        QtCore.QMetaObject.connectSlotsByName(Frame_user_login)

    def retranslateUi(self, Frame_user_login):
        _translate = QtCore.QCoreApplication.translate
        Frame_user_login.setWindowTitle(_translate("Frame_user_login", "帐号登录"))
        self.cb_server.setItemText(0, _translate("Frame_user_login", "安卓"))
        self.cb_server.setItemText(1, _translate("Frame_user_login", "ios"))
        self.cb_server.setItemText(2, _translate("Frame_user_login", "台服"))
        self.cb_server.setItemText(3, _translate("Frame_user_login", "日服"))
        self.cb_server.setItemText(4, _translate("Frame_user_login", "国际服"))
        self.label_4.setText(_translate("Frame_user_login", "请输入游戏账号和密码"))
        self.bt_close.setText(_translate("Frame_user_login", "登录"))

