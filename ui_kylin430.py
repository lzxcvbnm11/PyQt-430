# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""

from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QMainWindow,  QMessageBox
from PyQt5 import QtWidgets
from Ui_ui_kylin430 import Ui_MainWindow

from ctypes import *
cfun = CDLL("./WinC/adder.dll")

import sys
import time
import serial
import serial.tools.list_ports

class MainWindow(QMainWindow, Ui_MainWindow):
    """
    Class documentation goes here.
    """
    def __init__(self, parent=None):
        """
        Constructor
        
        @param parent reference to the parent widget
        @type QWidget
        """
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
    
    @pyqtSlot()
    def on_pushButton_clicked(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    def lzx_test(self):
        print("lzx add test function")
        
    @pyqtSlot()
    def on_pushButton_4_portcheck_clicked(self):
        """
        Slot documentation goes here.
        """
        """
        串口检测
        """
        print("cfun" + str(cfun.add_int(1, 2)))
        print("lzx add check clicked")
        # 检测所有存在的串口，将信息存储在字典中
        self.Com_Dict = {}
        port_list = list(serial.tools.list_ports.comports())
        self.comboBox_2.clear()
        for port in port_list:
            self.Com_Dict["%s" % port[0]] = "%s" % port[1]
            self.comboBox_2.addItem(port[0])
        if len(self.Com_Dict) == 0:
            self.label_43.setText(self.lable43_str + " 无串口")
      
        # TODO: not implemented yet
       
        
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())
