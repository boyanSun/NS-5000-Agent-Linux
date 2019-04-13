#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import socket
import time
import threading
import os
import commands
from utilsCommon import get_prefix
from utilsCommon import get_host_ip
from utilsCommon import pf_warn as pf_monitor
from utilsCommon import PrntLog
from utilsCommon import Config_agent
from utilsCommon import os_version
from utilsCommon import get_hardware_thresholdvalue
from StateInfo import MobTemp
from StateInfo import FanSpeed
from auditOper import auditOper
import traceback

import subprocess
import pdb
#pdb.set_trace()

import select
import socket
import Queue

from KafkaTransfer import Kafka_producer
from KafkaTransfer import Kafka_consumer
from ctypes import *

import ctypes
import re
from UsbParser import UsbDevice
from UsbParser import UsbInterface
from UsbParser import get_usb_devs

if not (os_version["type"] == "redhat" and os_version["version"] == 5):
    from pyudev import Context, Monitor
    import pyudev

failed_login_list = []
g_usbdev_list = []

def proc_failed_login(c_ip, c_user, c_time, l_port):
    global failed_login_list
    #dict = {'id':'172.16.140.34:root', 'time':[0,1,3,4]}
    #清空超时的记录
    failed_login_list = [i for i in failed_login_list if c_time - i['time'][-1] <= 15*60]

    for item in failed_login_list:
        if item['id'] == c_ip + ':' + c_user:
            # 去除早期的所有记录
            item['time'] = [i for i in item['time'] if c_time - i <= 15*60]
            item['time'].append(c_time)
            # 5条记录时告警，并删除此条记录
            if len(item['time']) == 5:
                msg = c_ip + ' ' + get_host_ip() + ' ' + l_port + ' ' + c_user
                pf_monitor.sendmsg("<4> " + get_prefix() + " 5 33 " + msg)
                PrntLog.info('proc_failed_login:5 33 %s' % msg )
                failed_login_list.remove(item)
                item.clear()
            return
    # 首次记录
    failed_login_list.append({'id':c_ip + ':' + c_user, 'time':[c_time]})
    return

net_monitor = ctypes.cdll.LoadLibrary('./libnet_monitor.so')
net_monitor.net_monitor.restype = ctypes.c_char_p
net_monitor_ret = ''

# wrap hello to make sure the free is done
def netmonitorfunc():
    _result = net_monitor.net_monitor()
    result = ctypes.c_char_p(_result).value
    return result

def net_info(perf):
    global net_monitor_ret
    while True:
        ret = netmonitorfunc()
        if ret == net_monitor_ret:
            continue
        net_monitor_ret = ret
        try:
            if re.search(' down', ret):
                pf_monitor.sendmsg("<4> " + get_prefix() + " 5 26 " + ret)
                PrntLog.info('net_info:5 26 %s' % ret )
            elif re.search(' up', ret):
                pf_monitor.sendmsg("<4> " + get_prefix() + " 5 27 " + ret)
                PrntLog.info('net_info:5 27 %s' % ret )
        except Exception as e:
            PrntLog.error('Failed net_info ret: %s error: %s' % (ret, e))

def serial_info(perf):
    serial_list = []
    PrntLog.info("serial_info!")
    #print ("serial_info!")
    while True:
        try:
            time.sleep(3)
            (status, serial) = commands.getstatusoutput("lsof /dev/ttyS[0-9]|grep /dev/")
            if "status error" in serial:
                PrntLog.info("there is no serial in this server")
                break
            if serial == "":
                #print "serial not used."
                if len(serial_list) != 0:
                    for s in serial_list:
                        pf_monitor.sendmsg("<5> " + get_prefix() + " 5 20 0 " + s)
                        PrntLog.info('serial_info:5 20 0 ' +s )
                        #print ('serial_info:5 20 0 ' +s )
                serial_list = []
                continue
            serial = serial.split("\n")
            new_serial_list = []
            for line in serial:
                if "/dev/ttyS" not in line:
                    continue
                name = line.split("/")[-1]
                if name not in new_serial_list:
                    new_serial_list.append(name)
                if name not in serial_list:
                    pf_monitor.sendmsg("<4> " + get_prefix() + " 5 19 1 " + name)
                    PrntLog.info('serial_info:5 19 1 ' + name)
                    #print ('serial_info:5 19 1 ' + name)
            for s in serial_list:
                if s not in new_serial_list:
                    pf_monitor.sendmsg("<5> " + get_prefix() + " 5 20 0 " + s)
                    PrntLog.info('serial_info:5 20 0 ' + s)
                    #print ('serial_info:5 20 0 ' + s)
            serial_list = new_serial_list
        except Exception as e:
            PrntLog.error('serial_info error :%s, cmdoutput :%s' % (e, serial))
            #print ('serial_info error :%s, cmdoutput :%s' % (e, serial))

def parallel_info(perf):
    parallel_list = []
    PrntLog.info("parallel_info!")
    while True:
        try:
            time.sleep(3)
            (status, parallel) = commands.getstatusoutput("lsof /dev/parport[0-9] | grep /dev/")
            if "status error" in parallel:
                PrntLog.info("there is no parallel in this server")
                break
            if parallel == "":
                #print "serial not used."
                if len(parallel_list) != 0:
                    for s in parallel_list:
                        pf_monitor.sendmsg("<5> " + get_prefix() + " 5 22 0 " + s)
                        PrntLog.info('parallel_info:5 22 0 ' +s )
                        #print ('serial_info:5 20 0 ' +s )
                parallel_list = []
                continue
            parallel = parallel.split("\n")
            new_parallel_list = []
            for line in parallel:
                if "/dev/parport" not in line:
                    continue
                name = line.split("/")[-1]
                if name not in new_parallel_list:
                    new_parallel_list.append(name)
                if name not in parallel_list:
                    pf_monitor.sendmsg("<4> " + get_prefix() + " 5 21 1 " + name)
                    PrntLog.info('parallel_info:5 21 1 ' + name)
                    #print ('serial_info:5 19 1 ' + name)
            for s in parallel_list:
                if s not in new_parallel_list:
                    pf_monitor.sendmsg("<5> " + get_prefix() + " 5 22 0 " + s)
                    PrntLog.info('parallel_info:5 22 0 ' + s)
                    #print ('serial_info:5 20 0 ' + s)
            parallel_list = new_parallel_list
        except Exception as e:
            PrntLog.error('parallel_info error :%s, cmdoutput :%s' % (e, parallel))
            #print ('serial_info error :%s, cmdoutput :%s' % (e, serial))

def is_vaildip(ipstr):
    try:
        if len(ipstr.split( '.' ))!=4:
            return False
        return all( map( lambda x: -1 < x < 256, map( int, ipstr.split( '.' ) ) ) )
    except:
        return False

#获取主机网络连接状态信息
def get_foreignIp_netstat():
    foreignIpList =[]
    cmdline = '/usr/local/sagent-3000-ns/netstat -tpn | grep ESTABLISHED '
    fp = os.popen( cmdline )
    for line in fp:
        if 'ESTABLISHED' not in line:
            continue
        ipDict={}
        strList = line.split( ' ' )
        i = 0
        for i in range( len( strList ) ):
            str = strList[i]
            if str.find( ':' ) >= 0:
                ipDict['LOCAL_IP']=str.split( ':' )[0]
                ipDict['LOCAL_PORT']=str.split( ':' )[1]
                break

        for j in range( i + 1, len( strList ) ):
            str = strList[j]
            if str.find( ':' ) >= 0:
                ipDict['FOREIGN_IP'] = str.split( ':' )[0]
                ipDict['FOREIGN_PORT'] = str.split( ':' )[1]
                break
        if (not is_vaildip(ipDict['LOCAL_IP'])) or (not is_vaildip(ipDict['FOREIGN_IP'])):
            continue

        foreignIpList.append(ipDict)
    fp.close()
    return foreignIpList

#获取IP地址白名单配置
def get_white_ip_list():
    whiteipList=[]
    try:
        ipconfigList = Config_agent.items( 'ip_list_white' )
    except Exception as e:
        PrntLog.error('illegal_connection get while ip list Failed. ')
        raise Exception( 'illegal_connection get while ip list Failed.' )

    for info in ipconfigList:
        whiteipList.append(info[1])
    PrntLog.info('illegal_connection white ip List: %s  '%whiteipList)
    return whiteipList

def ip2num(ip):#ip to int num
    lp = [int(x) for x in ip.split('.')]
    return lp[0] << 24 | lp[1] << 16 | lp[2] << 8 | lp[3]

def iprange(ipBegin,ipEnd,ipString):
    numBegin = ip2num(ipBegin)
    numEnd = ip2num(ipEnd)
    numIp=ip2num(ipString)
    if numIp>=numBegin and numIp<=numEnd:
        return True
    else:
        return False

def judge_ip_in_whitelist(ipString,whiteipList):
    for info in whiteipList:
        if info == '':
            continue
        elif info.find( '-' ) >= 0:
            if len(info.split('-'))!=2:
                continue
            ipBegin=info.split('-')[0]
            ipEnd=info.split('-')[1]
            if is_vaildip(ipBegin) and is_vaildip(ipEnd) and  iprange(ipBegin,ipEnd,ipString):
               return True
        else:
            if not is_vaildip(info):
                continue
            if ip2num( ipString )== ip2num( info ):
                return True
    return False

#非法外联告警
def illegal_connection(whiteipList):
    try:
        foreignIpList=get_foreignIp_netstat()
        for ipDict in foreignIpList:
            if not judge_ip_in_whitelist(ipDict['FOREIGN_IP'],whiteipList):
                PrntLog.info('illegal_connection  %s'%ipDict)
                string=ipDict['LOCAL_IP']+' '+ipDict['LOCAL_PORT']+' '+ipDict['FOREIGN_IP']+' '+ipDict['FOREIGN_PORT']
                pf_monitor.sendmsg( "<1> " + get_prefix( ) + " 5 25 " + string )
                time.sleep(0.5)
    except Exception as e:
        PrntLog.error('illegal_connection Failed %s'%e)

#U盘存储 未禁用：FALSE  禁用：TRUE
def checkUSBStorage():
    cmdline = "ls /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko >/dev/null 2>&1"
    ret1 = os.system( cmdline ) >> 8

    cmdline = "lsmod |grep usb_storage >/dev/null 2>&1"
    ret2 = os.system( cmdline ) >> 8

    if ret1 == 0 or ret2 == 0:
        pf_monitor.sendmsg( "<2> " + get_prefix( ) + " " + '5 36 1' )
        PrntLog.info( 'USBStorage 5 36 1' )
        return False

    return True

def checkTempStatus(tempthresholdValue):
    resultDict=MobTemp()
    warnDict={}
    for key in resultDict:
        if float(resultDict[key]) > tempthresholdValue:
            warnDict[key] = resultDict[key]

    if len(warnDict) == 0:
        return

    ret=''
    for (key,value) in warnDict.items( ):
        ret = '%s %s %s' % (ret, key, value)
    strLine='<2> %s 5 30 %s%s' % (get_prefix( ),tempthresholdValue,ret)
    pf_monitor.sendmsg(strLine)
    PrntLog.info( 'Temp warn %s'% (strLine) )

def checkFanStatus(fanthresholdValue):
    resultDict=FanSpeed()
    warnDict={}
    for key in resultDict:
        if float(resultDict[key]) < fanthresholdValue:
            warnDict[key] = resultDict[key]

    if len(warnDict) == 0:
        return

    ret=''
    for (key,value) in warnDict.items( ):
        ret = '%s %s %s' % (ret, key, value)

    strLine = '<2> %s 5 31 %s%s' % (get_prefix( ), fanthresholdValue, ret)
    pf_monitor.sendmsg( strLine )
    PrntLog.info( 'fanSpeed warn %s' % (strLine) )

'''
ipmi-sensors  |grep 'Power Supply'
96: PS Redundancy (Power Supply): [Redundancy Lost]
97: Status (Power Supply): [Presence detected][Power Supply input lost (AC/DC)]
98: Status (Power Supply): [Presence detected]

ipmi-sensors  |grep 'Power Supply'
96: PS Redundancy (Power Supply): [Fully Redundant (formerly "Redundancy Regained")]
97: Status (Power Supply): [Presence detected]
98: Status (Power Supply): [Presence detected]
'''
def checkPowerStatus():
    (status, output) = commands.getstatusoutput( "ipmi-sensors | grep '(Power Supply):'" )
    if status != 0:
        return ''
    tempList = output.split( '\n' )
    for tempLine in tempList:
        if 'OK' in tempLine:
            continue

        if 'lost' in tempLine or 'Lost' in tempLine:
            pf_monitor.sendmsg( "<1> " + get_prefix( ) + " " + '5 32'  )
            PrntLog.info( 'power warn 5 32')
            return

def checkHardwareStatus():
    (tempthresholdValue, fanthresholdValue)=get_hardware_thresholdvalue()
    checkTempStatus(tempthresholdValue)
    checkFanStatus(fanthresholdValue)
    checkPowerStatus()


def warn_check_info(perf):
    whiteipList = get_white_ip_list( )
    while True:
        illegal_connection(whiteipList)
        checkUSBStorage()
        checkHardwareStatus()
        time.sleep(60)

class State:
    cdrom_state = -1
    def __init__(self):pass

    @staticmethod
    def get_usb_info(device):
        usbkou = device.get('DEVPATH')
        usbkou = usbkou[usbkou.find('usb')+5:usbkou.find('usb')+5+3]
        model = device['ID_MODEL'].replace('_',' ')
        vendor = device['ID_VENDOR'].replace('_',' ')
        model_id = device['ID_MODEL_ID'].replace('_',' ')
        vendor_id = device['ID_VENDOR_ID'].replace('_',' ')

        jiekou_no = device.get('DEVPATH')
        jiekou_no = jiekou_no[jiekou_no.find(usbkou+':'):jiekou_no.find(usbkou+':')+7]
        wangkou_no = device.get('SUBSYSTEM')
        if 'block' in wangkou_no:
            wangkou_no = '08'
        else:
            wangkou_no = '01'

        type = device.get('DEVTYPE')
        if 'disk' in type:
            type = '0'
        else:
            type = '1'

        serial = device['ID_SERIAL']
        return '{'+usbkou+'}{'+model+'}{'+vendor+'}{'+model_id+'}{'+vendor_id+'}{<'+jiekou_no+'@'+wangkou_no+'>}{'+type+'}'

def usb_check(action):
    global g_usbdev_list
    change_state = '0'
    # 根据usbdev的个数变化判断插拔
    u_list = get_usb_devs()
    o = []
    n = []
    for i in g_usbdev_list:
        o.append(i.fname)
    for i in u_list:
        n.append(i.fname)
    # 从差集中获取fname
    removed_fname = list(set(o).difference(set(n)))
    added_fname = list(set(n).difference(set(o)))
    # 根据fname获取usbdev
    if action == 'remove' and len(removed_fname) > 0:
        change_state = '2'
        for i in g_usbdev_list:
            if i.fname == removed_fname[0]:
                usbdev = i
                break
    elif action == 'add' and len(added_fname) > 0:
        change_state = '1'
        for i in u_list:
            if i.fname == added_fname[0]:
                usbdev = i
                break
    if change_state == '0':
        return
    g_usbdev_list = u_list
    usb_port_num = usbdev.fname
    product_name = usbdev.productname
    manufacturer_name = usbdev.manufacturername
    pid = str("%04x" % usbdev.pid)
    vid = str("%04x" % usbdev.vid)
    i_name = usbdev.interfaces[0].fname
    i_num = str("%02x" % usbdev.interfaces[0].iclass)
    if usbdev.interfaces[0].iclass == 8:
        type = '0'
    elif usbdev.interfaces[0].iclass == 3:
        type = '1'
    else:
        type = '2'
    string = change_state + ' {' + usb_port_num + '}{' + product_name + '}{' + manufacturer_name + '}{' + pid + '}{' + vid + '}{<' + i_name + '@' + i_num + '>}{' + type + '}'
    # print string

    if change_state == '1':
        logType = '17'
        UStatus = '4'
    elif change_state == '2':
        logType = '18'
        UStatus = '5'
    else:
        return

    pf_monitor.sendmsg("<%s> %s 5 %s %s" % (UStatus, get_prefix(), logType, string))
    PrntLog.info('device_event:5 %s %s' % (logType, string))

def device_event(action, device):
    if device.get("ID_CDROM") == "1" and device.get("DEVTYPE") == 'disk':
        if device.get('ID_FS_USAGE') != None:
            if State.cdrom_state != 1:
                State.cdrom_state = 1
                str1 = str(device.get('ID_MODEL'))
                str2 = str(device.get('ID_FS_LABEL').encode('UTF-8'))
                pf_monitor.sendmsg("<4> " + get_prefix()+ " 5 23 0 " + str1 + ' ' + str2)
                PrntLog.info('device_event:5 23 0 %s %s' % (str1,str2) )
        else:
            if State.cdrom_state != 0:
                State.cdrom_state = 0
                string = str(device.get('ID_MODEL'))
                pf_monitor.sendmsg("<5> " + get_prefix()+ " 5 24 1 " + string )
                PrntLog.info('device_event:5 24 1 %s' % string )
    else:
        if device.get("ID_BUS") != 'usb':
            return
        usb_check(action)

def check_cdrom():
    (status, outputs) = commands.getstatusoutput('cat /proc/mounts |grep iso9660')
    if outputs == "":
        return "0"
    else:
        return "1"

def getcdromname():
    output = commands.getoutput("cat /proc/mounts |grep iso9660")
    cdromList = output.split()
    cdromname = "CDROM"
    for index in range(len(cdromList)):
        if cdromList[index] == "iso9660":
            cdromname = cdromList[index-1].split("/")[-1].replace(' ', '-')
            break
    return cdromname

def warning_info_5(perf):
    scan_cdrom = False
    devname = ""
    cdromstate = check_cdrom()
    try:
        # 电科院测试服务器ubuntu 8.04系统udevmonitor没有cdrom事件
        #if os_version["name"] == "ubuntu" and os_version["version"] == 8:
        if True:
            scan_cdrom = True
            (status, outputs) = commands.getstatusoutput('cat /proc/scsi/scsi')
            lines = outputs.split("\n")
            for i in range(0, len(lines)):
                line = lines[i]
                if "Type:" in line and "CD-ROM" in line:
                    devname = lines[i-1].split("Model:")[-1].split("Rev:")[0].lstrip().rstrip().replace(" ", "_")
                    #print devname
                    break
        udev_monitor_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        udev_monitor_sock.bind('\x00/org/kernel/udev/monitor')
        inputs = [udev_monitor_sock]
        outputs = []
    except Exception as e:
        PrntLog.error('warning_info init Failed %s' % e)
        #print ('warning_info init Failed %s' % e)
        return

    while True:
        try:
            readable, writable, exceptional = select.select(
                inputs, outputs, inputs, 1)

            if scan_cdrom:
                new_state = check_cdrom()
                if (new_state != cdromstate):
                    if new_state == '1':
                        cdromname = getcdromname()
                        pf_monitor.sendmsg("<4> " + get_prefix() + " 5 23 0 " + devname + ' ' + cdromname)
                        PrntLog.info("CDROM: <4> " + get_prefix() + " 5 23 0 " + devname + ' ' + cdromname)
                    else:
                        pf_monitor.sendmsg("<5> " + get_prefix() + " 5 24 1 " + devname)
                        PrntLog.info("CDROM: <5> " + get_prefix() + " 5 24 1 " + devname)
                    cdromstate = new_state

            if not (readable or writable or exceptional):
                continue;

            for s in readable:
                data = s.recv(4096)
                # print data

            lines = []
            while '\x00' in data:
                line, data = data.split('\x00', 1)
                lines.append(line)
                # print line

            d = dict(s.split('=') for s in lines[1:])

            if not scan_cdrom:
                # cdrom
                if 'SUBSYSTEM' in d.keys() and d['SUBSYSTEM'] == 'block' \
                        and 'PHYSDEVBUS' in d.keys() and d['PHYSDEVBUS'] == 'scsi' \
                        and 'PHYSDEVDRIVER' in d.keys() and d['PHYSDEVDRIVER'] == 'sr':
                    (status, devname) = commands.getstatusoutput('cat /sys' + d['PHYSDEVPATH'] + '/model')
                    devname = devname.replace(' ', '-')
                    # print devname
                    if d['ACTION'] == 'mount':
                        cdromstate = '1'
                        #(status, cdromname) = commands.getstatusoutput('blkid /dev/sr0 | awk -F \"\\\"\" \'{print $2}\'')
                        #cdromname = cdromname.replace(' ', '-')
                        cdromname = getcdromname()
                        pf_monitor.sendmsg("<4> " + get_prefix() + " 5 23 0 " + devname + ' ' + cdromname)
                        PrntLog.info("CDROM: <4> " + get_prefix() + " 5 23 0 " + devname + ' ' + cdromname)
                    else:
                        cdromstate = '0'
                        pf_monitor.sendmsg("<5> " + get_prefix() + " 5 24 1 " + devname)
                        PrntLog.info("CDROM: <5> " + get_prefix() + " 5 24 1 " + devname)

            # USB
            if 'ID_BUS' in d.keys() and d['ID_BUS'] == 'usb':
                usb_check(d['ACTION'])

        except Exception as e:
            PrntLog.error('warning_info_5 internal Failed %s' % e)
            PrntLog.error("warning_info_5 fail: %s" % traceback.format_exc())

def warning_info_6(perf):
    try:
        State()
        context = Context()
        monitor = Monitor.from_netlink(context)
        monitor.start()
    except Exception as e:
        PrntLog.error('warning_info init failed: %s ' % e)
    while True:
        try:
            for device in iter(monitor.poll, None):
                device_event(device.action, device)
        except Exception as e:
            PrntLog.error('warning_info device_event failed: %s ' % e)
            PrntLog.error("warning_info_6 fail: %s" % traceback.format_exc())

def warning_info(perf):
    try:
        global g_usbdev_list
        g_usbdev_list = get_usb_devs()
    except Exception as e:
        PrntLog.error('g_usbdev_list read Failed %s' % e)
        return
    if os_version["type"] == "redhat" and os_version["version"] == 5:
        warning_info_5(perf)
    else:
        warning_info_6(perf)

def check_process(name):
    cmd = "ps -ef|grep \"" + name + "\""
    (status, ret) = commands.getstatusoutput(cmd)
    ret = ret.split("\n")
    for item in ret:
        if "grep" not in item:
            return True
    return False 

def proc_command_execve_log(looptime):
    system_command_list = []
    network_service_process_list = []
    sshd_state = check_process("/usr/sbin/sshd")
    #获取主机系统命令调用配置和主机网络服务开启
    try:
        scconfigList = Config_agent.items('system_command')
        for info in scconfigList:
            dict = {"exe":info[1], "last_time":""}
            system_command_list.append(dict)
    except Exception as e:
        PrntLog.error('audit_command_execve get system_command Failed. ')
        raise Exception('audit_command_execve get system_command Failed.')
    try:
        nsconfigList = Config_agent.items('network_service')
        for info in nsconfigList:
            dict = {"service":info[1].split(":")[0],"exe":info[1].split(":")[-1], "last_time":""}
            network_service_process_list.append(dict)
    except Exception as e:
        PrntLog.error('audit_command_execve get network_service Failed. ')
        raise Exception('audit_command_execve get network_service Failed.')

    # 查询审计规则
    while True:
        time.sleep(looptime)
        for item in system_command_list:
            (last_time, callerdictlist) = auditOper.proc_log_by_executable_name(item["exe"], item["last_time"], looptime)
            if last_time > item["last_time"]:
                item["last_time"] = last_time
                for caller in callerdictlist:
                    if caller["pid"] == "1":
                        continue
                    string = "<2> %s 5 39 %s %s %s"%(get_prefix(), caller["pid"], caller["exe"], item["exe"])
                    pf_monitor.sendmsg(string)
                    PrntLog.info('system_command_msg: %s' % string)
                    #print ('system_command_msg: %s' % string)

        for item in network_service_process_list:
            if item["exe"] == "sshd":
                new_state = check_process("/usr/sbin/sshd")
                if new_state != sshd_state:
                    sshd_state = new_state
                    if new_state:
                        string = "<2> %s 4 21 %s 1" % (get_prefix(), item["service"])
                        pf_monitor.sendmsg(string)
                        PrntLog.info('network_service_msg: %s' % string)
                        #print ('network_service_msg: %s' % string)
            continue
    
            (last_time, callerdictlist) = auditOper.proc_log_by_executable_name(item["exe"], item["last_time"], looptime)
            if last_time > item["last_time"]:
                item["last_time"] = last_time
                for caller in callerdictlist:
                    #规避fork出来的进程
                    if caller["pid"] != "1":
                        continue
                    string = "<2> %s 4 21 %s 1" % (get_prefix(), item["service"])
                    pf_monitor.sendmsg(string)
                    PrntLog.info('network_service_msg: %s' % string)
                    #print ('network_service_msg: %s' % string)


if __name__ == '__main__':
    warning_info(60)
