import sys
import time
import serial
import serial.tools.list_ports
import re

from ctypes import *
import ctypes

cfun=CDLL('WinC/adder.so')
kylin_api = CDLL('kylin_api.so')

ser = serial.Serial()
Com_Dict = {}
port_list = list(serial.tools.list_ports.comports())
for port in port_list:
    Com_Dict["%s" % port[0]] = "%s" % port[1]
if len(Com_Dict) == 0:
    print("not find com")
    
"""   
开启串口
"""
com_port = port_list[0]
#print("------" + str(com_port))
com_port = str(com_port)[0:4]
#print("-------" + com_port)
ser.port = com_port
ser.baudrate = 9600
ser.bytesize = 8
ser.stopbits = 1
ser.parity = "N"

try:
    ser.open()
except:
    print( "Port Error", "此串口不能被打开！")
    sys.exit(1)
    
#print( "串口使用 串口初始化，请等待十秒再进行操作")

"""
for i  in range(0, len(sys.argv)):
    print(sys.argv[i])
"""    
if ser.isOpen():
    tx_len = 0
    if len(sys.argv) > 1:
        tx_len = int(sys.argv[1])
   
    #1 读取文件内容，写入com
    print("tx_len")
    com_buf_tag = c_char * 16
    com_rx_buf = com_buf_tag()
    cfun.get_tx_buf.argtypes = [POINTER(c_char), c_int]
    cfun.get_tx_buf(com_rx_buf, 16)
   
    num = ser.write(com_rx_buf)
    print("py serial write num = "+ str(num))
  
    time.sleep(0.1)
    try:
        num = ser.inWaiting()
    except:
        ser.close()
        sys.exit()
    if num > 0:
        data = bytes()
        data = ser.read(num)
        num = len(data)
        print("rx num "+ str(num))
        cfun.set_rx_buf.argtypes = [POINTER(c_char), c_int]
        cfun.set_rx_buf(data, num)
        
        # hex显示
        out_s = ''
       
        for i in range(0, len(data)):
            out_s = out_s + '{:02X}'.format(data[i]) + ' '
        #print("recv:")
        print(out_s)
        #print("reclen:" + str(len(data)))
        if len(data) != 16:
           print("com read error num not is 16")
           sys.exit()
        str_strip = out_s[-12:-1].replace(" ",  "")
        #print("str_strip=", str_strip)
        my_val = int(str_strip,  16)  >> 5
        print("%x"%(my_val))
    ser.close()


