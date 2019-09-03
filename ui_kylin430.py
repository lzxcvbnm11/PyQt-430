# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""
import sys, os
if hasattr(sys, 'frozen'):
    os.environ['PATH'] = sys._MEIPASS + ";" + os.environ['PATH'] + ";" + os.path.abspath(__file__)
from ctypes import *
from ctypes import cdll
import ctypes
import socket

p = os.getcwd() + './WinC/adder.so'
cfun = cdll.LoadLibrary(p)
#cfun=CDLL('adder.so')
p = os.getcwd() + './WinC/kylin_api.so'
kylin_api = cdll.LoadLibrary(p)
#kylin_api = CDLL('kylin_api.so')
from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QMainWindow,  QMessageBox
from PyQt5 import QtWidgets
from Ui_ui_kylin430 import Ui_MainWindow

import time
import serial
import serial.tools.list_ports
import re
import threading
ser = serial.Serial()
class PTP_PORT_config(Structure):
    _fields_ = [
    ('stream_type', c_uint8),
    ('stream_data_type', c_uint8),    #确定是ipv4 ipv6 和 二层报文
    ('cast_type', c_uint8),               #是单播还是多播
    ('vlan_type', c_uint8),               #确定是几层valn
    ('outertpid', c_uint16), 
    ('outervlan', c_uint16), 
    ('innervlan', c_uint16),
    ('vlan', c_uint16),  
    ('smac_correct', c_uint8), 
    ('sip_correct', c_uint8), 
    ('local_port_correct', c_uint8),
    ('source_port_correct', c_uint8),
    ('flow', c_uint32), 
    ('slave_select', c_uint8), 
    ]
class ptp_table4_tag(Structure):
    _fields_ = [
    ('mac', c_uint8 * 6), 
    ('tpid', c_uint16), 
    ('outervlan', c_uint16), 
    ('innervlan', c_uint16), 
    ]
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
    ptp_port0_config = PTP_PORT_config()
    ptp_port1_config = PTP_PORT_config()
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
        #cfun.run_python()
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
        com_port = port_list[0]
        print("------" + str(com_port))
        com_port = str(com_port)[0:4]
        print("-------" + com_port)
        ser.port = com_port
        ser.baudrate = 9600
        ser.bytesize = 8
        ser.stopbits = 1
        ser.parity = "N"
        try:
            ser.open()
        except:
            print( "Port Error", "此串口不能被打开！")
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
            self.ptp_port0_config.smac_correct = 1
            #print("test ---" + str(self.ptp_port0_config.smac_correct))
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
            self.ptp_port0_config.smac_correct = 0
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
        # current select is ipv4 or ipv6
        if self.ptp_stream_type == 1 or self.ptp_stream_type == 4:
            compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
            if compile_ip.match(ipaddr):
                print("ipv4 correnct")
                self.ptp_port0_config.sip_correct = 1
                ptp_port0_config.sip
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
                self.ptp_port0_config.sip_correct = 0
                print("ipv4 is error")
        #ipv6
        elif self.ptp_stream_type == 2 or self.ptp_stream_type == 5:
            compile_ip = re.compile('^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$')
            if compile_ip.match(ipaddr):
                print("correnct")
                self.ptp_port0_config.sip_correct = 1
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
        self.ptp_port0_config.cast_type = 1
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
        kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
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
            ptp_port0_config.local_port_correct = 1
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
            ptp_port0_config.local_port_correct = 0
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
            ptp_port0_config.source_port_correct = 0
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
            ptp_port0_config.source_port_correct = 0
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
        self.ptp_port0_config.cast_type = 0
        #config msg_ctrl
        kylin_api.kylin_ptp_msg_cast_ctl_set.argvtypes = [c_uint32, c_uint32,  c_uint32 , c_uint32]
        kylin_api.kylin_ptp_msg_cast_ctl_set(0, cast_type, announce_index, event_index)
        #config table 1 业务模板内容
        
    @pyqtSlot(str)
    def on_lineEdit_dmac_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        """
        flow 0
        """ 
        ip_format_error =  "correct"
        mac_format_error = "correct"
        vlan_format_error = "correct"
        out_vlan_format_error = "correct"
        tpid_format_error = "correct"
        
        # setup 1 构建白名单buff 和组播mac buf    
        whiletable_type = c_uint8 *  18
        whiletable_buf = whiletable_type() 
        multicast_mac_buf = whiletable_type()
        for i in range(6):
            multicast_mac_buf[i] = 0
            
        multicast_mac_buf[0] = 0x01
        multicast_mac_buf[1] = 0x1b
        multicast_mac_buf[2] = 0x19
        #setup 2 获取vlan信息
        type = self.ptp_port0_config.vlan_type * 3 + self.ptp_port0_config.stream_data_type
        """
        self.lineEdit_ClockLevel.setValidator(QtGui.QIntValidator())
        text = self.lineEdit_ClockLevel.text()
        if  text.isdecimal() == False:
            return
        clock_level = int (self.lineEdit_ClockLevel.text())
        kylin_api.kylin_ptp_clocklevel_set.argvtypes = [c_uint32, c_uint32]
        kylin_api.kylin_ptp_clocklevel_set(0, clock_level)
        """
        vlan_type = 1 #是否带有vlan #------------notice this is not complete
        vlan = 0
        out_vlan = 0
        tpid = 0
        if vlan_type == 1:
            #------------notice this is not complete
            vlan = 1
        #------------notice this is not complete
        elif vlan_type == 2:
            vlan = 1
            out_vlan = 2
            tpid = 3
        #steup 3 获取dmac信息
        mac_type = c_uint8 * 6
        mac_buf = mac_type()
        SMAC = self.lineEdit_Smac0.text()
        compile_mac=re.compile('^[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}:[A-Fa-f\d]{2}$')
        if compile_mac.match(SMAC):
            print("mac correnct")
            #print("test ---" + str(self.ptp_port0_config.smac_correct))
            mac_list = SMAC.split(":", SMAC.count(":"))
            for i in range(0, SMAC.count(":") + 1):
                mac_list[i] = "0x" + mac_list[i]
                print("%x"%(int(mac_list[i], 16)))
                tmp = int(mac_list[i], 16) & 0xff
                mac_buf[i] = tmp
                #mask is 0xff
                #whiletable_buf[index] = (tmp<< 8) | 0xff
        else:
            mac_format_error = "error"
            print("mac have error")
        
        #setup 4 set dip
        ipaddr = self.lineEdit_SIP.text()
        dip_type = c_uint8 * 16
        dip_buf = sip_type()
        # current select is ipv4 or ipv6
        if self.ptp_stream_type == 1 or self.ptp_stream_type == 4:
            compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
            if compile_ip.match(ipaddr):
                print("ipv4 correnct")
                ptp_port0_config.sip
                dip_list = ipaddr.split(".", ipaddr.count("."))
                for i in range(0, ipaddr.count(".") + 1):
                    dip_list[i] = int(dip_list[i])
                    dip_buf[i] = dip_list[i] & 0xff
                    print("%d"%(sip_buf[i]))
            else:
                ip_format_error = "error"
                print("ipv4 is error")
        #ipv6
        elif self.ptp_stream_type == 2 or self.ptp_stream_type == 5:
            compile_ip = re.compile('^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){6}(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|([0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){0,4}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3})|(:(:[0-9A-Fa-f]{1,4}){0,5}:(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}))$')
            if compile_ip.match(ipaddr):
                print("correnct")
                dip_buf = self.upack_ipv6(ipaddr)
            else:
                ip_format_error = "error"
                print("error")
        #setup 5 检查格式错误
        if ptp_port0_config.local_port_correct != 1 or ptp_port0_config.sip_correct != 1 or ptp_port0_config.smac_correct != 1 or ptp_port0_config.source_port_correct != 1:
            if ptp_port0_config.local_port_correct != 1:
                local_port_format = "error"
            else:
                local_port_format = "correct"
            if ptp_port0_config.sip_correct != 1:
                sip_format = "error"
            else:
                sip_format = "correct"
            if ptp_port0_config.smac_correct != 1:
                smac_format = "error"
            else:
                smac_format = "correct"
            if ptp_port0_config.source_port_correct != 1:
                source_port_format = "error"
            else:
                source_port_format = "correct"
            buf1 = "local port format" + local_port_format + "sip format" + sip_format + "smac format" + smac_format + "source port format" + source_port_format
        if ip_format_error == "error" or  mac_format_error  == "error" or vlan_format_error == "error" or out_vlan_format_error == "error" or tpid_format_error == "error":
            buf = "dip format " + ip_format_error + "mac format" + mac_format_error + "vlan format" + vlan_format_error + "out vlan format" + out_vlan_format_error + "tpid format" + tpid_format_error
        #setup 6 pack whiletable_buf
        #无vlan
        if vlan_type == 0:
            for i in range(6):
                whiletable_buf[i] = mac_buf[i]
        #一层vlan
        elif vlan_type == 1:
            whiletable_buf[0] = (vlan >> 8) & 0xff
            whiletable_buf[1] = vlan&0xff
            for i in range(6):
                index = i + 2
                whiletable_buf[index] = mac_buf[i]
        #2层vlan
        elif vlan_type == 2:
            #tpisd
            whiletable_buf[0] = (tpid >> 8) & 0xff
            whiletable_buf[1] = tpid&0xff
            #out_vlan
            whiletable_buf[0] = (out_vlan >> 8) & 0xff
            whiletable_buf[1] = out_vlan&0xff
            #innervlan
            whiletable_buf[0] = (vlan >> 8) & 0xff
            whiletable_buf[1] = vlan&0xff
            for i in range(6):
                index = i + 6
                whiletable_buf[index] = mac_buf[i] 
                
        kylin_api.kylin_ptp_whitetable_set.argtypes = [c_uint32,c_uint32, c_uint32,  POINTER(c_uint16)]
        kylin_api.kylin_smac_set(0, 0, type, whiletable_buf)
        
        # setup 7 set dipS
        #ipv4
        if ptp_port0_config.stream_data_type == 1:
            # 判断是不是slave口
            if ptp_port0_config.slave_select == 0:
                kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
                reg_write = cmd_reg_t()
                reg_write.reg = 0x5c4940
                reg_write.data = (dip_buf[0] << 24) |  (dip_buf[1] << 16) |  (dip_buf[2] << 8) |  (dip_buf[3])  
                kylin_api.kylin_reg_set(byref(reg_write), 1)
            else:
                kylin_api.kylin_ptp_table5_set.argtypes = [c_uint32,c_uint32, POINTER(c_uint8)]
                kylin_api.kylin_ptp_table5_set(0, 0, dip_buf)
        elif ptp_port0_config.stream_data_type == 2:
            if ptp_port0_config.slave_select == 0:
                kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
                reg_write = cmd_reg_t()
                reg_write.reg = 0x5c4940
                reg_write.data = (dip_buf[0] << 24) |  (dip_buf[1] << 16) |  (dip_buf[2] << 8) |  (dip_buf[3])  
                kylin_api.kylin_reg_set(byref(reg_write), 1)
                reg_write.reg = 0x5c4944
                reg_write.data = (dip_buf[4] << 24) |  (dip_buf[5] << 16) |  (dip_buf[6] << 8) |  (dip_buf[7])  
                kylin_api.kylin_reg_set(byref(reg_write), 1)
                reg_write.reg = 0x5c4948
                reg_write.data = (dip_buf[8] << 24) |  (dip_buf[9] << 16) |  (dip_buf[10] << 8) |  (dip_buf[11])  
                kylin_api.kylin_reg_set(byref(reg_write), 1)
                reg_write.reg = 0x5c494c
                reg_write.data = (dip_buf[12] << 24) |  (dip_buf[13] << 16) |  (dip_buf[14] << 8) |  (dip_buf[15])  
                kylin_api.kylin_reg_set(byref(reg_write), 1)
            else:
                kylin_api.kylin_ptp_table5_set.argtypes = [c_uint32,c_uint32, POINTER(c_uint8)]
                kylin_api.kylin_ptp_table5_set(0, 0, dip_buf)
        #this is coonfig whitetable
        # port index type val 
       
            
        #setup 8 build table4    
        #config table 4 config dmac and vlan
        table4 = ptp_table4_tag()
        for i in range(0, 6):
            #判断组播还是单播，组播mac是固定的
            if ptp_port0_config.cast_type == 1:
                table4.mac[i] = mac_buf[i]
            elif ptp_port0_config.cast_type == 0:
                table4.mac[i] = multicast_mac_buf[i]
        #一层vlan
        if vlan_type == 1:
            table4.innervlan  = vlan
        #2层vlan
        elif vlan_type == 2:
            #tpisd
            table4.innervlan = vlan
            #out_vlan
            table4.outervlan = out_vlan
            #innervlan
            table4.tpid = tpid
            
        kylin_api.kylin_ptp_table4_set.argvtypes = [c_uint32, c_uint32, POINTER(ptp_table4_tag)]
        kylin_api.kylin_ptp_table4_set(0, 0, byref(table4))
        
        #setup 9 set dmac reg 
        kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
        reg_write = cmd_reg_t()
        reg_write.reg = 0x5c6938
        #判断组播还是单播，组播mac是固定的
        if ptp_port0_config.cast_type == 1:
            reg_write.data = (mac_buf[0] << 8) | mac_buf[1]
        elif ptp_port0_config.cast_type == 0:
            reg_write.data = (multicast_mac_buf[0] << 8) | multicast_mac_buf[1]
        kylin_api.kylin_reg_set(byref(reg_write), 1)
        
        reg_write.reg = 0x5c693c
        #判断组播还是单播，组播mac是固定的
        if ptp_port0_config.cast_type == 1:
            reg_write.data = (mac_buf[2] << 24) |  (mac_buf[3] << 16) |  (mac_buf[4] << 8) |  (mac_buf[5]) 
        elif ptp_port0_config.cast_type == 0:
            reg_write.data = (multicast_mac_buf[2] << 24) |  (multicast_mac_buf[3] << 16) |  (multicast_mac_buf[4] << 8) |  (multicast_mac_buf[5]) 
        kylin_api.kylin_reg_set(byref(reg_write), 1)
        
        kylin_api.kylin_reg_set(byref(reg_write), 1)
         
        #setup 10 配置组播vlan
        kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
        reg_write = cmd_reg_t()
        reg_write.reg = 0x5c4950
        reg_write.data = (out_vlan << 16) | vlan
        kylin_api.kylin_reg_set(byref(reg_write), 1)
        
        reg_write.reg = 0x5c4954
        reg_write.data = tpid
        kylin_api.kylin_reg_set(byref(reg_write), 1)

    
    @pyqtSlot(str)
    def on_lineEdit_dip_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        
                
    @pyqtSlot()
    def on_checkBox_flow0_clicked(self):
        """
        Slot documentation goes here.
        """
        """
        kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
        reg_write = cmd_reg_t()
        reg_write.reg = 0x5c4aa0
        reg_write.data = 6
        """
        kylin_api.kylin_ptp_table0_set.argvtypes = [c_uint32, c_uint32, c_uint32, c_uint32, c_uint32, c_uint32]
        kylin_api.kylin_ptp_table0_set(0, 1, 10, 0x84, 2)
        # 如果是组播  加在slave 判断 的组播vlan  0x5c4950 
    
    
    @pyqtSlot(str)
    def on_lineEdit_vlan_textChanged(self, p0):
        """
        Slot documentation goes here.
        
        @param p0 DESCRIPTION
        @type str
        """
        #注意组播的话 DMAC是固定的
        vlan_text = self.lineEdit_vlan.text()
        vlan = int(vlan_text)
        outvlan_text = self.lineEdit_outvlan.text()
        outvlan = int(outvlan_text)
        tpid_text = self.lineEdit_tpid.text()
        tpid = int(tpid_text)
        #一层vlan
        if self.ptp_port0_config.vlan_type == 1:
            kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
            reg_write = cmd_reg_t()
            reg_write.reg = 0x5c4950
            reg_write.data = vlan
            kylin_api.kylin_reg_set(byref(reg_write), )
        elif self.ptp_port0_config.vlan_type == 2:
            kylin_api.kylin_reg_set.argvtypes = [POINTER(cmd_reg_t), c_int]
            reg_write = cmd_reg_t()
            reg_write.reg = 0x5c4950
            reg_write.data = vlan
            kylin_api.kylin_reg_set(byref(reg_write), )
            
"""
这是创建线程，读取socket
"""
HOST = ''
PORT = 50007
def serial_read(com_rx_buf):
    print("-------serial read--------")
    num = ser.write(com_rx_buf)
    print("py serial write num = "+ str(num))
  
    time.sleep(0.1)
    try:
        num = ser.inWaiting()
        print("num = %d"%(num))
    except:
        print("error waiting timeout")
        ser.close()
        sys.exit()
    if num > 0:
        data = bytes()
        data = ser.read(num)
        num = len(data)
        print("rx num "+ str(num))
        
        # hex显示
        out_s = ''
       
        for i in range(0, len(data)):
            out_s = out_s + '{:02X}'.format(data[i]) + ' '
        #print("recv:")
        #print(out_s)
        #print("reclen:" + str(len(data)))
        if len(data) != 16:
           print("com read error num not is 16")
           sys.exit()
        str_strip = out_s[-12:-1].replace(" ",  "")
        #print("str_strip=", str_strip)
        my_val = int(str_strip,  16)  >> 5
        print("%x"%(my_val))
        print(data)
        return data
def socket_deal_com():
    print("aaa")
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM ) as ser_fd:
        print("socket creat ok")
        ser_fd.bind((HOST, PORT))
        localIP = socket.gethostbyname(socket.gethostname())
        print ("local ip address: %s"%localIP)
        sip_type = c_uint8 * 16
        sip_buf = sip_type()
        sip_list = localIP.split(".", localIP.count("."))
        for i in range(0, localIP.count(".") + 1):
            sip_list[i] = int(sip_list[i])
            sip_buf[i] = sip_list[i] & 0xff
        cfun.py_udp_ip_set.argvtypes = [POINTER(c_char)]
        cfun.py_udp_ip_set(sip_buf)
        while True:
            
#            addr = ('192.168.1.22', 12345)
#            er_fd.sendto(b"Good bye!\n", addr)
            data,  addr = ser_fd.recvfrom(1024)
            print("Received from %s:%s"%addr)
            print(data)
            
            read_data = serial_read(data)
            print("1111111111111111111")
            ser_fd.sendto(read_data, addr)
    
"""      
try:
   thread.start_new_thread( socket_deal_com, ("Thread-1", 2, ) )
except:
   print ("Error: unable to start thread" )  
 """  

if __name__ == "__main__":
    
    try:
       t1 = threading.Thread(target=socket_deal_com)
       t1.start()
    except:
       print ("Error: unable to start thread" )  
    app = QtWidgets.QApplication(sys.argv)
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())
    
    
