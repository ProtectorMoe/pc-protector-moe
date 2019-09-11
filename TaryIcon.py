from PyQt5.QtWidgets import QSystemTrayIcon, QMenu, QAction
from PyQt5.QtGui import QIcon
import PyQt5.sip
import os


class TrayIcon(QSystemTrayIcon):
    def __init__(self, parent=None):
        super(TrayIcon, self).__init__(parent)
        self.icon = QIcon('icon/icon.png')
        self.setIcon(self.icon)
        self.menu = QMenu()
        self.action_show = QAction('显示', self, triggered=self.active_show)
        self.action_close = QAction('退出', self, triggered=self.active_close)
        self.menu.addAction(self.action_show)
        self.menu.addAction(self.action_close)
        self.setContextMenu(self.menu)

    def active_show(self):
        if self.parent().isVisible():
            self.parent().hide()
        else:
            self.parent().show()

    def active_close(self, ):
        os._exit(0)

