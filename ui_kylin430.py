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
from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QMainWindow,  QMessageBox
from PyQt5 import QtWidgets
from Ui_ui_kylin430 import Ui_MainWindow

import time
import serial
import serial.tools.list_ports
import re
import IPy
class ClockIdentity(Structure):
    _fields_ = [
    ('id', c_uint8 * 8)
    ]
class PortIdentity(Structure):
    _fields_ = [
    ('clockId',ClockIdentity ), 
    ('portnum', c_uint16), 
    ]
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
    ptp_stream_type = 0
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

        compile_mac=re.compile('^[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}$')
        
        if compile_mac.match(SMAC):
            print("mac correnct")
            mac_type = c_uint8 *  6
            mac_buf = mac_type()
            mac_list = SMAC.split(":", SMAC.count(":"))
            for i in range(0, SMAC.count(":") + 1):
                mac_list[i] = "0x" + mac_list[i]
                print("%x"%(int(mac_list[i], 16)))
                mac_buf[i] = int(mac_list[i], 16) & 0xff
            
            kylin_api.kylin_smac_set.argtypes = [c_uint, POINTER(c_uint8)]
            kylin_api.kylin_smac_set(0, mac_buf)
        else:
            print("mac error")
            
    def upack_ipv6(self, ipaddr):
        ipaddr_len = len(ipaddr)
        # not use :: is 7    use ::  : num <= 7
        cnt = 7 - ipaddr.count(":")
        cnf_flag = 0
        sip_type = c_char * 16
        sip_buf = sip_type()
        ipv6_offset = ipaddr.find("::", 0, ipaddr_len)
        
        if ipv6_offset != -1:
            for i in range(0, ipv6_offset):
                if ipaddr[i] == ':':
                    cnf_flag = cnf_flag + 1
                    print("cnf_flag " + str(cnf_flag))
            sip_list = ipaddr.split(":", ipaddr.count(":"))   
            for i in range(0,ipaddr.count(":") + 1):
                print(sip_list[i])
                if i == (cnf_flag + 1):
                    
                    for k in range(0, cnt):
                        i = k + i
                        index = 2 * i
                        sip_buf[i] = 0
                        #print("%x"%(sip_buf[i]))
                        index = index + 1
                        sip_buf[index] = 0
                        print(":: index = " + str(index))
                        #print("%x"%(sip_buf[index]))
                    print(" i = " + str(i))
                elif i <=  cnf_flag :
                    sip_list[i] = "0x" + sip_list[i]
                    tmp = int(sip_list[i], 16)
                    index = i*2
                    sip_buf[index] = tmp & 0xff
                    #print("%x"%(sip_buf[index]))
                    index = index + 1
                    sip_buf[index] = ((tmp >> 8) & 0xff)
                    #print("%x"%(sip_buf[index]))
                elif i > cnf_flag:
                    print("--- i = " + str(i))
                    if  sip_list[i] != "":
                        print("--- i = " + str(i))
                        sip_list[i] = "0x" + sip_list[i]
                        tmp = int(sip_list[i], 16)
                        index = (i + cnt + 1 - 1)*2
                        print("index = " + str(index))
                        sip_buf[index] = tmp & 0xff
                        #print("%x"%(sip_buf[index]))
                        index = index + 1
                        sip_buf[index] = ((tmp >> 8) & 0xff)
                    #print("%x"%(sip_buf[index]))
                    
        else:
            sip_list = ipaddr.split(":", ipaddr.count(":"))
            for i in range(0, ipaddr.count(":") + 1):
                print(sip_list[i])
                sip_list[i] = "0x" + sip_list[i]
                tmp = int(sip_list[i], 16)
                index = i*2
                sip_buf[index] = tmp & 0xff
                #print("%x"%(sip_buf[index]))
                index = index + 1
                sip_buf[index] = ((tmp >> 8) & 0xff)
                #print("%x"%(sip_buf[index]))
                    
        return sip_buf
                
        
    @pyqtSlot(str)
    def on_lineEdit_SIP_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        ipaddr = self.lineEdit_SIP.text()
        isipv4 = 0
        isipv6 = 0
        # current select is ipv4 or ipv6
        if self.ptp_stream_type == 1 or self.ptp_stream_type == 4:
            compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
            if compile_ip.match(ipaddr):
                print("ipv4 correnct")
                sip_type = c_uint8 * 16
                sip_buf = sip_type()
                sip_list = ipaddr.split(".", ipaddr.count("."))
                for i in range(0, ipaddr.count(".") + 1):
                    sip_list[i] = int(sip_list[i])
                    sip_buf[i] = sip_list[i] & 0xff
                    print("%d"%(sip_buf[i]))
                kylin_api.kylin_sip_set.argvtypes = [c_int, POINTER(c_uint8)]
                kylin_api.kylin_sip_set(0, sip_buf)
                
            else:
                print("ipv4 is error")
        #ipv6
        elif self.ptp_stream_type == 2 or self.ptp_stream_type == 5:
            compile_ip = re.compile('^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$')
            if compile_ip.match(ipaddr):
                print("correnct")
                sip_type = c_uint8 * 16
                sip_buf = sip_type()
                sip_buf = self.upack_ipv6(ipaddr)
                kylin_api.kylin_sip_set.argvtypes = [c_int, POINTER(c_uint8)]
                kylin_api.kylin_sip_set(0, sip_buf)
            else:
                print("error")
        """
        compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
        if compile_ip.match(ipaddr):
            print("ip correnct")
        else:
            print("ip error")
        """
        
        """
        IPV6
        ^([\\da-fA-F]{1,4}:){7}([\\da-fA-F]{1,4})$
        ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$
        """
        
        """
        compile_ip = re.compile('^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$')
        if compile_ip.match(ipaddr):
            print("correnct")
        else:
            print("error")
        """
        
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
        announce_index = self.comboBox_announce_rate.currentIndex()
        event_index = self.comboBox_event_rate.currentIndex()
        cast_type = self.radioButton_unicast.isChecked()
        kylin_api.kylin_ptp_msg_cast_ctl_set.argvtypes = [c_uint32, c_uint32,  c_uint32 , c_uint32]
        kylin_api.kylin_ptp_msg_cast_ctl_set(0, cast_type, announce_index, event_index)
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
        
    @pyqtSlot(str)
    def on_comboBox_stream_type_currentIndexChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        #print(p0)
        self.ptp_stream_type = self.comboBox_stream_type.currentIndex()
        kylin_api.kylin_ptp_header_set.argvtypes = [c_uint32,c_uint32,c_uint32,c_uint32,c_uint32, ]
        kylin_api.kylin_ptp_header_set(1, 0, 2, 0, self.ptp_stream_type + 1)
        #print(str(self.ptp_stream_type))
    @pyqtSlot(str)
    def on_lineEdit_ClockLevel_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        self.lineEdit_ClockLevel.setValidator(QtGui.QIntValidator())
        text = self.lineEdit_ClockLevel.text()
        if  text.isdecimal() == False:
            return
        clock_level = int (self.lineEdit_ClockLevel.text())
        kylin_api.kylin_ptp_clocklevel_set.argvtypes = [c_uint32, c_uint32]
        kylin_api.kylin_ptp_clocklevel_set(0, clock_level)
        

    @pyqtSlot(str)
    def on_lineEdit_Priority1_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        self.lineEdit_Priority1.setValidator(QtGui.QIntValidator())
        text = self.lineEdit_Priority1.text()
        if  text.isdecimal() == False:
            return
        priority = int (self.lineEdit_Priority1.text())
        kylin_api.kylin_ptp_priority1_set.argvtypes = [c_uint32, c_uint32]
        kylin_api.kylin_ptp_priority1_set(0, priority)
    
    @pyqtSlot(str)
    def on_lineEdit_Priority2_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        self.lineEdit_Priority2.setValidator(QtGui.QIntValidator())
        text = self.lineEdit_Priority2.text()
        if  text.isdecimal() == False:
            return
        priority = int (self.lineEdit_Priority2.text())
        kylin_api.kylin_ptp_priority2_set.argvtypes = [c_uint32, c_uint32]
        kylin_api.kylin_ptp_priority2_set(0, priority)
    
    @pyqtSlot(str)
    def on_lineEdit_PortId_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        portid_text = self.lineEdit_PortId.text()
        #portid = re.compile('([1-9|A-F|a-f]{2}:){9}[1-9|A-F|a-f]{2}')
        portid = re.compile('^([1-9A-Fa-f]{2}:){9}[1-9A-Fa-f]{2}$')
        
        if portid.match(portid_text):
            print("port is correct")
            portid_type = c_uint8 * 10
            portid_buf = portid_type()
            portid_list = portid_text.split(":", portid_text.count(":"))
            for i in range(0, portid_text.count(":") + 1):
                portid_list[i] = "0x" + portid_list[i]
                portid_buf[i] = int(portid_list[i], 16)
                print(str(int(portid_list[i], 16)))
                kylin_api.kylin_ptp_local_portId_set.argvtypes = [c_uint32, POINTER(c_uint8)]
                kylin_api.kylin_ptp_local_portId_set(0, portid_buf)
        else:
            print("port is eror")
            
    @pyqtSlot(str)
    def on_lineEdit_sourcePortId_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        portid_text = self.lineEdit_sourcePortId.text()
        #portid = re.compile('([1-9|A-F|a-f]{2}:){9}[1-9|A-F|a-f]{2}')
        portid = re.compile('^([1-9A-Fa-f]{2}:){9}[1-9A-Fa-f]{2}$')
        
        if portid.match(portid_text):
            print("port is correct")
            portid_type = c_uint8 * 10
            portid_buf = portid_type()
            portid_list = portid_text.split(":", portid_text.count(":"))
            for i in range(0, portid_text.count(":") + 1):
                portid_list[i] = "0x" + portid_list[i]
                portid_buf[i] = int(portid_list[i], 16)
                print(str(int(portid_list[i], 16)))
                portId = PortIdentity()
                for i in range(0, 7):
                    portId.clockId.id[i] = portid_buf[i]
                portId.portnum = (portid_buf[8] << 8) | portid_buf[9]
                
                kylin_api.kylin_ptp_bmc_sourceportId_set.argvtypes = [c_uint32, PortIdentity]
                kylin_api.kylin_ptp_bmc_sourceportId_set(0, portId)
        else:
            print("port is eror")
            
    @pyqtSlot(int)
    def on_comboBox_announce_rate_currentIndexChanged(self, index):
        """
        Slot documentation goes here.
        
        @param index DESCRIPTION
        @type int
        """
        #不确定value的值怎么填
        announce_index = self.comboBox_announce_rate.currentIndex()
        event_index = self.comboBox_event_rate.currentIndex()
        cast_type = self.radioButton_unicast.isChecked()
        kylin_api.kylin_ptp_msg_cast_ctl_set.argvtypes = [c_uint32, c_uint32,  c_uint32 , c_uint32]
        kylin_api.kylin_ptp_msg_cast_ctl_set(0, cast_type, announce_index, event_index)
        
    
    @pyqtSlot(int)
    def on_comboBox_event_rate_currentIndexChanged(self, index):
        """
        Slot documentation goes here.
        
        @param index DESCRIPTION
        @type int
        """
        announce_index = self.comboBox_announce_rate.currentIndex()
        event_index = self.comboBox_event_rate.currentIndex()
        cast_type = self.radioButton_unicast.isChecked()
        kylin_api.kylin_ptp_msg_cast_ctl_set.argvtypes = [c_uint32, c_uint32,  c_uint32 , c_uint32]
        kylin_api.kylin_ptp_msg_cast_ctl_set(0, cast_type, announce_index, event_index)
    
    @pyqtSlot(bool)
    def on_radioButton_multicase_clicked(self, checked):
        """
        Slot documentation goes here.
        
        @param checked DESCRIPTION
        @type bool
        """
        announce_index = self.comboBox_announce_rate.currentIndex()
        event_index = self.comboBox_event_rate.currentIndex()
        cast_type = self.radioButton_unicast.isChecked()
        kylin_api.kylin_ptp_msg_cast_ctl_set.argvtypes = [c_uint32, c_uint32,  c_uint32 , c_uint32]
        kylin_api.kylin_ptp_msg_cast_ctl_set(0, cast_type, announce_index, event_index)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())
    
    
