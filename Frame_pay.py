# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Frame_pay.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Frame_pay(object):
    def setupUi(self, Frame_pay):
        Frame_pay.setObjectName("Frame_pay")
        Frame_pay.resize(707, 372)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon/icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Frame_pay.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(Frame_pay)
        self.centralwidget.setObjectName("centralwidget")
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(10, 330, 691, 31))
        self.groupBox.setTitle("")
        self.groupBox.setObjectName("groupBox")
        self.label_3 = QtWidgets.QLabel(self.groupBox)
        self.label_3.setGeometry(QtCore.QRect(260, 10, 181, 16))
        self.label_3.setObjectName("label_3")
        self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_2.setGeometry(QtCore.QRect(10, 10, 691, 311))
        self.groupBox_2.setTitle("")
        self.groupBox_2.setObjectName("groupBox_2")
        self.label_2 = QtWidgets.QLabel(self.groupBox_2)
        self.label_2.setGeometry(QtCore.QRect(210, 10, 211, 281))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap("icon/wxpay.jpg"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")
        self.label = QtWidgets.QLabel(self.groupBox_2)
        self.label.setGeometry(QtCore.QRect(10, 10, 201, 281))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("icon/zfbpay.jpg"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        self.label_4 = QtWidgets.QLabel(self.groupBox_2)
        self.label_4.setGeometry(QtCore.QRect(430, 10, 251, 281))
        self.label_4.setText("")
        self.label_4.setPixmap(QtGui.QPixmap("icon/hb.png"))
        self.label_4.setScaledContents(True)
        self.label_4.setObjectName("label_4")
        Frame_pay.setCentralWidget(self.centralwidget)

        self.retranslateUi(Frame_pay)
        QtCore.QMetaObject.connectSlotsByName(Frame_pay)

    def retranslateUi(self, Frame_pay):
        _translate = QtCore.QCoreApplication.translate
        Frame_pay.setWindowTitle(_translate("Frame_pay", "打赏作者"))
        self.label_3.setText(_translate("Frame_pay", "您的支持就是我最大的动力,谢谢!"))

