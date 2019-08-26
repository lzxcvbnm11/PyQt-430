# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""


import sys, os
if hasattr(sys, 'frozen'):
    os.environ['PATH'] = sys._MEIPASS + ";" + os.environ['PATH'] + ";" + os.path.abspath(__file__)
from ctypes import *
import ctypes

cfun=CDLL('WinC/adder.so')
kylin_api = CDLL('kylin_api.so')
from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QMainWindow,  QMessageBox
from PyQt5 import QtWidgets
from Ui_ui_kylin430 import Ui_MainWindow

import time
import serial
import serial.tools.list_ports
import binascii
import re
import IPy
class cmd_reg_t(Structure):
    _fields_ = [
    ('reg', c_int), 
    ('data', c_int), 
    ]
class Version_st(Structure):
    _fields_ = [
    ('a', c_int), 
    ('b', c_int), 
    ('c', c_int), 
    ]
class MainWindow(QMainWindow, Ui_MainWindow):
    """
    Class documentation goes here.
    """
    PTP_1588_BASE_ADDR = 0x5c4800
    MAC_PHY_BASE_ADDR = 0x5c400
        
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
    @pyqtSlot(str)
    def on_lineEdit_Smac0_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        
        SMAC = self.lineEdit_Smac0.text()
        isHexRes = re.search('[^0-9|a-f|A-F]', SMAC, 0)
        
        if isHexRes == None and SMAC != None:
            SMAC = "0x" + SMAC
            print(SMAC)
            SMAC = int(SMAC, 16)
            print("data = " + str(SMAC))
            
       
    @pyqtSlot(str)
    def on_lineEdit_SIP_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        ipaddr = self.lineEdit_SIP.text()
        
        """
        compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
        if compile_ip.match(ipaddr):
            print("correnct")
        else:
            print("error")
        """
        
        """
        IPV6
        ^([\\da-fA-F]{1,4}:){7}([\\da-fA-F]{1,4})$
        ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$
        """
        compile_ip = re.compile('^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$')
        if compile_ip.match(ipaddr):
            print("correnct")
        else:
            print("error")
        
        """
        try:
            IPy.IP(ipaddr)
            print("correct")
        except Exception as e:
            print("error")
        """

    @pyqtSlot(bool)
    def on_radioButton_unicast_clicked(self, checked):
        """
        Slot documentation goes here.
        
        @param checked DESCRIPTION
        @type bool
        """
        print("unicast is checked")
        print("cfun" + str(cfun.add_int(1, 2)))
        print("lzx add check clicked")
        self.lineEdit_53.setReadOnly(1)
        multicast = QtWidgets.QLineEdit(self.lineEdit_53)
        multicast.setFocusPolicy(QtCore.Qt.NoFocus)
        test_int_arr = c_int * 2
        test_int_arr_test = test_int_arr()
        cfun.test_change_int.argtypes = [POINTER(c_int)]
        print("this is test")
        cfun.test_change_int(test_int_arr_test)
        print("------------" + str(test_int_arr_test[1]))
        """
        kylin_api.kylin_reg_set.argtypes = [POINTER(cmd_reg_t), c_int]
        cmd_reg_set = cmd_reg_t()
        
        kylin_api.kylin_reg_set(byref(cmd_reg_set), tmp)

        kylin_api.kylin_version_get.argtypes=[POINTER(Version_st)]
        ver = Version_st()
        kylin_api.kylin_version_get(byref(ver) )
        
        
        print(str(ver.a) + str(ver.b) + str(ver.c))

        
        
        
        """
    @pyqtSlot()
    def on_pushButton_5_clicked(self):
        """
        Slot documentation goes here.
        """
        text = self.spinBox_5.value()
        reg = ctypes.c_int()
        reg = text
        cfun.py_serial_read.argtpyes = [c_int]
        cfun.py_serial_read(reg)
        
    

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())
    

