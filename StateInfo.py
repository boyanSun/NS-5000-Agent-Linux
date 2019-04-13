#!/usr/bin/python
# -*- coding: utf8 -*-
# import loggin
import threading
import time

import psutil
import os
import commands
import re
from utilsCommon import pf_monitor
from utilsCommon import get_prefix
import UsbParser
from UsbParser import UsbDevice
from UsbParser import UsbInterface
from UsbParser import get_usb_devs
from utilsCommon import PrntLog
from utilsCommon import os_version
import traceback

#if not (os_version["type"] == "redhat" and os_version["version"] == 5):
#    import sensors

# 状态日志为主机运行的动态信息，为可配置周期性发送(1分钟)，对于事件类的采集项，需要事件发送时即发送
class StateInfo( threading.Thread ):
    def __init__(self):
        threading.Thread.__init__( self )

    def run(self):
        while True:
            try:
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.cpuUsedInfo( ) )
                time.sleep(0.5)
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.pmemUsedInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.vmemUsedInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.DiskUsedInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.ethUsedInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.ModemInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.ZProcessInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.CloseWaitTCP( ) )
                time.sleep( 0.5 )
                lines = self.ConnectionInfo( )
                for item in lines:
                    if not item == '':
                        pf_monitor.sendmsg("<5> " + get_prefix() + " " + '4 13 ' + item)
                        PrntLog.info('ConnectionInfo:4 13 %s' % item )
                        time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.USBUsedInfo( ) )
                time.sleep( 0.5 )
                pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + self.CDROMUsedInfo( ) )
                time.sleep( 0.5 )
                try:
                    resultDict = MobTemp()
                    if len(resultDict) != 0:
                        ret=''
                        for (key, value) in resultDict.items( ):
                            ret='%s %s %s'%(ret,key,value)
                        pf_monitor.sendmsg("<5> " + get_prefix() + " " + '4 15' + ret)
                        PrntLog.info('MobTemp 4 15%s'%ret)
                    resultDict = FanSpeed()
                    if len(resultDict) != 0:
                        ret = ''
                        for (key, value) in resultDict.items( ):
                            ret = '%s %s %s' % (ret, key, value)
                        pf_monitor.sendmsg("<5> " + get_prefix() + " " + '4 16' + ret)
                        PrntLog.info( 'FanSpeed 4 16%s' % ret )
                except:
                    pass
                '''
                ret= self.getTcpNetFlow()
                if not ret == '':
                    pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + '4 19' + ret )
                    time.sleep( 0.5 )
                ret = self.getUdpNetFlow()
                if not ret == '':
                    pf_monitor.sendmsg( "<5> " + get_prefix( ) + " " + '4 20' + ret )
                    time.sleep( 0.5 )
                '''
            except Exception as e:
                PrntLog.error('StateInfo failed:%s' % e)
                PrntLog.error("StateInfo fail: %s" % traceback.format_exc())
            time.sleep( 60 )

    # CPU平均负载百分比
    def cpuUsedInfo(self):
        string = str( psutil.cpu_percent( interval=1 ) ) +"%"
        PrntLog.info('cpuUsedInfo:4 1 %s' % string)
        return "4 1 " + string

    # 内存类型ID<空格>已使用内存数
    def pmemUsedInfo(self):
        output = commands.getoutput( 'free -m' )
        outputList=output.split('\n')
        for line in outputList:
            if 'Mem:' in line:
                newList=",".join(line.split()).split(',')
                #print(newList)
                totalMem=float(newList[1])
                usedMem=float(newList[2])
                #print(totalMem,usedMem)
                percent = 100.0 * ((usedMem / totalMem))
                string = str( "%.2f" % percent ) + "%"
                PrntLog.info( 'pmemUsedInfo:4 2 1 %s' % string )
                return "4 2 1 " + string

    # 内存类型ID<空格>已使用内存数
    def vmemUsedInfo(self):
        output = commands.getoutput( 'free -m' )
        outputList = output.split( '\n' )
        for line in outputList:
            if 'Swap:' in line:
                newList=",".join(line.split()).split(',')
                totalMem = float( newList[1] )
                usedMem = float( newList[2] )
                if totalMem == 0 :
                    string =  "0%"
                else:
                    percent = 100.0 * ((usedMem / totalMem))
                    string = str( "%.2f" % percent ) + "%"
                PrntLog.info( 'vmemUsedInfo:4 2 2 %s' % string )
                return "4 2 2 " + string

    '''
    # 内存类型ID<空格>已使用内存数
    def pmemUsedInfo(self):
        phymem = psutil.virtual_memory( )
        info2 = psutil.swap_memory( )
        string = str( phymem.percent ) + "%"
        PrntLog.info('pmemUsedInfo:4 2 1 %s' % string)
        return "4 2 1 " + string

    # 内存类型ID<空格>已使用内存数
    def vmemUsedInfo(self):
        virmem = psutil.swap_memory( )
        string = str( virmem.percent ) + "%"
        PrntLog.info('vmemUsedInfo:4 2 2 %s' % string)
        return "4 2 2 " + string
'''
    # 硬盘容量使用率
    def DiskUsedInfo(self):
        disk = os.statvfs( "/" )
        capacity = disk.f_bsize * disk.f_blocks
        available = disk.f_bsize * disk.f_bavail
        used = disk.f_bsize * (disk.f_blocks - disk.f_bavail)
        percent = 100 * ((float( used ) / float( capacity )))
        # (status, percent) = commands.getstatusoutput('df -hl | grep G | awk \'/dev/ {sum += $2; used +=$3};END {print used/sum*100}\'')
        string = str( "%.2f" % percent ) + "%"
        PrntLog.info('DiskUsedInfo:4 3 %s' % string)
        return "4 3 " + string

    # 网卡1名称<空格>网卡状态<空格>网卡1接收数据量（long）<空格>网卡1发送数据量（long）<空格>网卡2名称<空格>网卡状态<空格>网卡2接收数据量（long）<空格>网卡2发送数据量（long）
    def ethUsedInfo(self):
        key_info = psutil.net_io_counters( pernic=True ).keys( )  # 获取网卡名称
        re = ""

        for key in key_info:
            re = re + str( key )
            # 网卡状态
            (status, spped) = commands.getstatusoutput( 'ethtool ' + str( key ) + ' | grep detected' )
            if "yes" in spped:
                re = re + " 1 "
            else:
                re = re + " 0 "
            re = re + str( psutil.net_io_counters( pernic=True ).get( key ).bytes_recv ) + " "  # 各网卡接收的字节数
            re = re + str( psutil.net_io_counters( pernic=True ).get( key ).bytes_sent )  # 各网卡发送的字节数
            re = re + " "
        PrntLog.info('ethUsedInfo:4 4 %s' % re)
        return "4 4 " + re

    # Modem使用情况<空格>Modem 名称
    def ModemInfo(self):
        # TODO
        PrntLog.info('ModemInfo:4 5 0 0')
        return "4 5 0 0 "

    @staticmethod
    def proc_starttime(pid):
        p = re.compile(r"^btime (\d+)$", re.MULTILINE)
        m = p.search(open("/proc/stat").read())
        btime = int(m.groups()[0])
        clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        stime = int(open("/proc/%s/stat" % pid).read().split()[21]) / clk_tck
        return btime + stime

    # 僵尸进程数量值 <空格>#僵尸进程名称1<空格>进程号<空格>父进程号 <空格>产生时间 <空格>进程路径 <空格>#僵尸进程名称2<空格>进程号<空格>父进程号 <空格>产生时间 <空格>进程路径
    def ZProcessInfo(self):
        count = 0
        procname = ''
        procpid = ''
        procppid = ''
        procstarttime = ''
        procpath = ''
        re = ''
        (status, pidset) = commands.getstatusoutput( 'ps -A -ostat,pid |grep -e \'^[Zz]\'| awk \'{print $2}\'' )
        if len(pidset) == 0:
            PrntLog.info('ZProcessInfo:4 11 0')
            return '4 11 0'
        list = pidset.split( '\n' )
        for pid in list:
            if not os.path.exists('/proc/'+pid):
                continue
            #(status, item) = commands.getstatusoutput( 'ps -ocomm,pid,ppid,lstart,cmd ' + pid + '| sed \'1d\'' )
            #re = re + item + " "
            count = count + 1
            (status, procname) = commands.getstatusoutput( 'ps -p ' + pid + ' -o comm=' )
            procname = procname.replace(' ', '_')
            procpid = pid
            (status, procppid) = commands.getstatusoutput( 'ps -p ' + pid + ' -o ppid=' )
            procppid = procppid.strip()
            procstarttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(StateInfo.proc_starttime(pid))))
            try:
                (status, procpath) = commands.getstatusoutput( 'readlink -f /proc/' + pid + '/exe' )
                #不是所有的进程都能够找到路径！
                if not procpath == '':
                    procpath = os.path.dirname(procpath)
                else:
                    procpath = procname
            except Exception as e:
                procpath = procname
            re = re + ' #' + procname + ' ' + procpid + ' ' + procppid + ' ' + procstarttime + ' ' + procpath
        PrntLog.info('ZProcessInfo:4 11 %s%s' % (str( count ),re))
        return "4 11 %s%s"% (str( count ),re)

    # TCP链接CLOSE_WAIT数量值
    def CloseWaitTCP(self):
        (status, count) = commands.getstatusoutput( '/usr/local/sagent-3000-ns/netstat -ano | grep CLOSE_WAIT | wc -l' )
        PrntLog.info('CloseWaitTCP:4 12 %s' % count)
        return "4 12 " + count

    # 协议<空格>本地IP<空格>本地端口<空格>远程IP<空格>远程端口<空格>连接状态<空格>进程编号<空格>服务名称
    def ConnectionInfo(self):
        ret = ""
        lines = []
        (status, output) = commands.getstatusoutput(
            '/usr/local/sagent-3000-ns/netstat -atnp | awk \'{print $1, $4, $5, $6,$7}\' | sed \'s/:/ /g\' | sed \'s/\// /g\' | sed \'1,2d\' | grep LISTEN' )

        while '\n' in output:
            line, output = output.split( '\n', 1 )
            if re.search('getnameinfo failed', line):
                continue
            #去除IPV6部分
            if len(line.split(' '))==8:
                lines.append( line )

        if not re.search('getnameinfo failed', output):
            if len(output.split(' '))==8:
                lines.append( output )

        return lines


    # 存储类USB使用数<空格>非存储类（键盘鼠标）USB使用数<空格>非存储类(其他)使用数
    def USBUsedInfo(self):
        usbstoragecnt = 0
        usbhidcnt = 0
        usbothercnt = 0
        usbdevs = get_usb_devs()
        for u in usbdevs:
            if u.interfaces[0].iclass == 8:
                usbstoragecnt = usbstoragecnt + 1
            elif u.interfaces[0].iclass == 3:
                usbhidcnt = usbhidcnt + 1
            else:
                usbothercnt = usbothercnt + 1

        PrntLog.info('USBUsedInfo:4 17 %s %s %s' % (str(usbstoragecnt),str(usbhidcnt),str(usbothercnt)))
        return "4 17 " + str(usbstoragecnt) + ' ' + str(usbhidcnt) + ' ' + str(usbothercnt)

    # 光驱使用情况
    # 使用状态<空格>光驱名称
    def CDROMUsedInfo(self):
        (status, output) = commands.getstatusoutput( 'cat /proc/scsi/scsi' )
        if output == '':
            PrntLog.info('CDROMUsedInfo:4 18 0 0')
            return "4 18 0 0"

        lines = []
        count = 0
        while '\n' in output:
            line, output = output.split( '\n', 1 )
            lines.append( line )
            count = count + 1
        lines.append( output )
        count = count + 1

        index = 0
        devnameList=[]
        for line in lines:
            if re.search( 'CD-ROM', line ):
                line1 = lines[index - 1]
                line1 = line1.split( 'Rev:' )[0].split( 'Model:' )[1].strip( ' ' )
                devname = line1.replace( ' ', '-' )
                devnameList.append(devname)
            index = index + 1

        if len(devnameList) == 0:
            PrntLog.info('CDROMUsedInfo:4 18 0 0')
            return "4 18 0 0"

        #RHEL 6
        (status, output) = commands.getstatusoutput( 'cat /proc/mounts|grep /dev/sr' )
        if output == '':
            state = '0'
            devname = devnameList[0]
        else:
            state = '1'
            indexStr=output.split()[0].split('/')[-1][2:]
            index=int(indexStr)
            if index < len(devnameList):
                devname=devnameList[index]
            else:
                devname=devnameList[0]

        PrntLog.info('CDROMUsedInfo:4 18 %s %s' % (state,devname))
        return '4 18 ' + state + ' ' + devname

    #TCP流量上报
    def getTcpNetFlow(self):
        datalist = []
        flag = 0
        r = os.popen( "/usr/local/sagent-3000-ns/netstat -s -t" )
        output = r.read( )
        flowlist = output.split( '\n' )
        for line in flowlist:
            if line == "Tcp:":
                flag = 1
                continue
            if flag == 1:
                data = line.lstrip( ' ' ).split( )[0]
                if data.isdigit( ):
                    datablank = " " + data
                    datalist.append( datablank )
                else:
                    break
        r.close( )
        String = ""
        if len( datalist ) >=10:
            for index in range( 10):
                String = String + datalist[index]

        PrntLog.info('getTcpNetFlow %s'%String)
        return String

    # UDP流量上报
    def getUdpNetFlow(self):
        datalist = []
        flag = 0
        r = os.popen( "/usr/local/sagent-3000-ns/netstat -s -u" )
        output = r.read( )
        flowlist = output.split( '\n' )
        for line in flowlist:
            if line == "Udp:":
                flag = 1
                continue
            if flag == 1:
                data = line.lstrip( ' ' ).split( )[0]
                if data.isdigit( ):
                    datablank = " " + data
                    datalist.append( datablank )
                else:
                    break
        r.close( )
        String = ""
        if len( datalist ) >= 4:
            for index in range( 4 ):
                String = String + datalist[index]

        PrntLog.info( 'getUdpNetFlow %s' % String )
        return String

'''
ipmi-sensors  |grep Temp
20: Inlet Temp (Temperature): 30.00 C (-7.00/47.00): [OK]
25: Exhaust Temp (Temperature): 32.00 C (3.00/75.00): [OK]
26: Temp (Temperature): 39.00 C (3.00/83.00): [OK]
27: Temp (Temperature): 23.00 C (NA/NA): [OK]
'''
#主板探测点序号<空格>主板探测点序号温度（摄氏度）
def MobTemp():
    (status, output)=commands.getstatusoutput("ipmi-sensors | grep '(Temperature):'")
    if status !=0:
        return ''
    tempList=output.split('\n')
    resultDict={}
    for tempLine in tempList:
        elementList=tempLine.split()
        seqNo=elementList[0].split(':')[0]
        tempValue=''
        for i in range(len(elementList)):
            if elementList[i] =='(Temperature):':
                tempValue = elementList[i+1]
                break

        if (tempValue =='0.00' and elementList[-1] == '[OK]') or tempValue == '' or tempValue == '[OK]' or 'NA' in tempValue:
            continue

        resultDict[seqNo] = tempValue
        #ret='%s %s %s '%(ret,seqNo,tempValue)
    return  resultDict

'''
ipmi-sensors  |grep Fan
14: Fan1 (Fan): 6840.00 RPM (360.00/NA): [OK]
15: Fan2 (Fan): 6720.00 RPM (360.00/NA): [OK]
16: Fan3 (Fan): 0.00 RPM (360.00/NA): [At or Below (<=) Lower Critical Threshold]
17: Fan4 (Fan): 6720.00 RPM (360.00/NA): [OK]
18: Fan5 (Fan): 6840.00 RPM (360.00/NA): [OK]
19: Fan6 (Fan): 6600.00 RPM (360.00/NA): [OK]
62: Fan Redundancy (Fan): [Fully Redundant (formerly "Redundancy Regained")]
'''
#风扇探测点序号<空格>风扇转数（每分钟转数rpm）
def FanSpeed():
    (status, output) = commands.getstatusoutput( "ipmi-sensors | grep '(Fan):'" )
    if status !=0:
        return ''
    fanList = output.split( '\n' )
    resultDict = {}
    for fanLine in fanList:
        elementList = fanLine.split( )
        seqNo = elementList[0].split( ':' )[0]
        fanValue = ''
        for i in range( len( elementList ) ):
            if elementList[i] == 'RPM' and elementList[i-2] != 'FAN':
                fanValue = elementList[i - 1]
                break

        if (fanValue == '0.00' and elementList[-1] == '[OK]') or fanValue == '':
            continue

        resultDict[seqNo] = fanValue
        #ret = '%s %s %s ' % (ret, seqNo, fanValue)

    return resultDict
