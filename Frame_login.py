# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Frame_login.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Frame_login(object):
    def setupUi(self, Frame_login):
        Frame_login.setObjectName("Frame_login")
        Frame_login.resize(395, 308)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon/icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Frame_login.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(Frame_login)
        self.centralwidget.setObjectName("centralwidget")
        self.tv_paper = QtWidgets.QLabel(self.centralwidget)
        self.tv_paper.setGeometry(QtCore.QRect(0, 0, 391, 281))
        self.tv_paper.setText("")
        self.tv_paper.setScaledContents(True)
        self.tv_paper.setObjectName("tv_paper")
        self.bt_login = QtWidgets.QPushButton(self.centralwidget)
        self.bt_login.setGeometry(QtCore.QRect(320, 250, 61, 24))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("icon/login.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.bt_login.setIcon(icon1)
        self.bt_login.setObjectName("bt_login")
        self.cb_server = QtWidgets.QComboBox(self.centralwidget)
        self.cb_server.setGeometry(QtCore.QRect(270, 230, 111, 22))
        self.cb_server.setObjectName("cb_server")
        self.bt_change_user = QtWidgets.QPushButton(self.centralwidget)
        self.bt_change_user.setGeometry(QtCore.QRect(270, 250, 51, 24))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("icon/server.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.bt_change_user.setIcon(icon2)
        self.bt_change_user.setObjectName("bt_change_user")
        self.tv_gameVersion = QtWidgets.QLabel(self.centralwidget)
        self.tv_gameVersion.setGeometry(QtCore.QRect(10, 240, 91, 20))
        self.tv_gameVersion.setText("")
        self.tv_gameVersion.setObjectName("tv_gameVersion")
        self.tv_selfVersion = QtWidgets.QLabel(self.centralwidget)
        self.tv_selfVersion.setGeometry(QtCore.QRect(10, 260, 91, 20))
        self.tv_selfVersion.setText("")
        self.tv_selfVersion.setObjectName("tv_selfVersion")
        Frame_login.setCentralWidget(self.centralwidget)
        self.statusBar = QtWidgets.QStatusBar(Frame_login)
        self.statusBar.setObjectName("statusBar")
        Frame_login.setStatusBar(self.statusBar)

        self.retranslateUi(Frame_login)
        QtCore.QMetaObject.connectSlotsByName(Frame_login)

    def retranslateUi(self, Frame_login):
        _translate = QtCore.QCoreApplication.translate
        Frame_login.setWindowTitle(_translate("Frame_login", "登录"))
        self.bt_login.setText(_translate("Frame_login", "登录"))
        self.bt_change_user.setText(_translate("Frame_login", "帐号"))

