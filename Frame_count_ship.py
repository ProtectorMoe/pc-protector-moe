# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Frame_count_ship.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Frame_count_ship(object):
    def setupUi(self, Frame_count_ship):
        Frame_count_ship.setObjectName("Frame_count_ship")
        Frame_count_ship.resize(696, 549)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("../Auto_JR_test/icon/icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Frame_count_ship.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(Frame_count_ship)
        self.centralwidget.setObjectName("centralwidget")
        self.table_count_ship = QtWidgets.QTableWidget(self.centralwidget)
        self.table_count_ship.setGeometry(QtCore.QRect(10, 40, 681, 501))
        self.table_count_ship.setObjectName("table_count_ship")
        self.table_count_ship.setColumnCount(4)
        self.table_count_ship.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.table_count_ship.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_count_ship.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_count_ship.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_count_ship.setHorizontalHeaderItem(3, item)
        self.cb_count_5 = QtWidgets.QCheckBox(self.centralwidget)
        self.cb_count_5.setGeometry(QtCore.QRect(20, 10, 61, 19))
        self.cb_count_5.setObjectName("cb_count_5")
        self.cb_count_4 = QtWidgets.QCheckBox(self.centralwidget)
        self.cb_count_4.setGeometry(QtCore.QRect(80, 10, 61, 19))
        self.cb_count_4.setObjectName("cb_count_4")
        self.cb_count_3 = QtWidgets.QCheckBox(self.centralwidget)
        self.cb_count_3.setGeometry(QtCore.QRect(140, 10, 81, 19))
        self.cb_count_3.setObjectName("cb_count_3")
        self.cb_count_2 = QtWidgets.QCheckBox(self.centralwidget)
        self.cb_count_2.setGeometry(QtCore.QRect(200, 10, 101, 19))
        self.cb_count_2.setObjectName("cb_count_2")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(300, 10, 41, 21))
        self.label.setObjectName("label")
        self.ed_point = QtWidgets.QLineEdit(self.centralwidget)
        self.ed_point.setGeometry(QtCore.QRect(350, 10, 113, 20))
        self.ed_point.setObjectName("ed_point")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(470, 10, 41, 21))
        self.label_2.setObjectName("label_2")
        self.ed_ship = QtWidgets.QLineEdit(self.centralwidget)
        self.ed_ship.setGeometry(QtCore.QRect(510, 10, 113, 20))
        self.ed_ship.setObjectName("ed_ship")
        self.bt_claen = QtWidgets.QPushButton(self.centralwidget)
        self.bt_claen.setGeometry(QtCore.QRect(630, 10, 61, 21))
        self.bt_claen.setObjectName("bt_claen")
        Frame_count_ship.setCentralWidget(self.centralwidget)

        self.retranslateUi(Frame_count_ship)
        QtCore.QMetaObject.connectSlotsByName(Frame_count_ship)

    def retranslateUi(self, Frame_count_ship):
        _translate = QtCore.QCoreApplication.translate
        Frame_count_ship.setWindowTitle(_translate("Frame_count_ship", "出货统计"))
        item = self.table_count_ship.horizontalHeaderItem(0)
        item.setText(_translate("Frame_count_ship", "时间"))
        item = self.table_count_ship.horizontalHeaderItem(1)
        item.setText(_translate("Frame_count_ship", "名称"))
        item = self.table_count_ship.horizontalHeaderItem(2)
        item.setText(_translate("Frame_count_ship", "位置"))
        item = self.table_count_ship.horizontalHeaderItem(3)
        item.setText(_translate("Frame_count_ship", "评价"))
        self.cb_count_5.setText(_translate("Frame_count_ship", "五星"))
        self.cb_count_4.setText(_translate("Frame_count_ship", "四星"))
        self.cb_count_3.setText(_translate("Frame_count_ship", "三星"))
        self.cb_count_2.setText(_translate("Frame_count_ship", "两星及以下"))
        self.label.setText(_translate("Frame_count_ship", "只看点:"))
        self.label_2.setText(_translate("Frame_count_ship", "只看船:"))
        self.bt_claen.setText(_translate("Frame_count_ship", "清空"))

