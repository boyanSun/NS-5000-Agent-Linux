#!/usr/bin/python
# -*- coding: utf8 -*-
import cpuinfo
import psutil
import os
import commands
import platform
import re
from utilsCommon import pf_monitor
from utilsCommon import get_prefix
from utilsCommon import PrntLog
from utilsCommon import os_version
import traceback

# 配置信息为主机的静态信息，不需要周期性发送，操作系统采集程序发送一次即可
class ConfigInfor(object):
    def __init__(self):
        timeout = 10

    def report(self):
        try:
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.cpuConfigInfo())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.memConfigInfo())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.DiskSizeInfo())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.ModemInfo())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.USBCountInfo())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.SerialCount())
            #pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.ParaCount())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.ethInfo())
            pf_monitor.sendmsg("<5> " + get_prefix() + " " + self.OSInfo())
        except Exception as e:
            PrntLog.error('ConfigInfor failed:%s' % e)
            PrntLog.error("ConfigInfor fail: %s" % traceback.format_exc())
        return

    # CPU数量以核为单位，CPU主频以GHz为单位，CPU缓存以MB/核为单位
    def cpuConfigInfo(self):
        info = cpuinfo.get_cpu_info()
        cores = info["count"]
        ghz = info["hz_advertised"].split(" ")[0]
        cachesize = str(float(info["l2_cache_size"].split(" ")[0])/1000)
        (status, cores) = commands.getstatusoutput('cat /proc/cpuinfo | grep "cpu cores" | head -1| cut -d ":" -f2 | sed "s/ //g"')
        if cores == "":
            cores = "1"
        (status, ghz) = commands.getstatusoutput('cat /proc/cpuinfo | grep "MHz" | head -1 |cut -d ":" -f2 | sed "s/ //g"')
        (status, cachesize) = commands.getstatusoutput(' cat /proc/cpuinfo | grep "cache size" | head -1 |cut -d ":" -f2  | cut -d " " -f2 | sed "s/ //g"')
        PrntLog.info( 'cpuConfigInfo:3 1 %s %s %s ' % (str(cores),ghz,cachesize) )
        return "3 1 "+ str(cores)+" "+ghz+" "+cachesize
 
    # 物理内存以GB为单位，虚拟内存数以GB为单位。
    def memConfigInfo(self):
        info1 = psutil.virtual_memory()
        info2 = psutil.swap_memory()
        str1 = str(float(info1.total)/1024/1024/1024)
        str2 = str(float(info2.total)/1024/1024/1024)
        PrntLog.info('memConfigInfo:"3 2 %s %s' % (str1 , str2) )
        return "3 2 "+ str1+" "+str2
 
    #硬盘容量以GB为单位。
    def DiskSizeInfo(self):
        #TODO 如果有多块磁盘，直接相加？
        size = 0
        with open('/proc/partitions', 'r') as dp:
            for disk in dp.readlines():
                if re.search(r'[s,h,v]d[a-z]\n', disk):
                    blknum = disk.strip().split(' ')[-2]
                    dev = disk.strip().split(' ')[-1]
                    size = size + int(blknum)

        total = str(round(float(size)/1024/1024, 2))
        #(status, size) = commands.getstatusoutput('df -hl | grep G | awk \'/dev/ {sum += $2};END {print sum}\'')
        PrntLog.info('DiskSizeInfo:3 3 %s' % total )
        return "3 3 "+ total
 
    #内置Modem数量<空格>外置Modem数量 
    def ModemInfo(self):
        (status, count ) = commands.getstatusoutput('ls /dev/modem* | grep -v "ls" | wc -l')
        if "modem" in count:
            count = "0"
        PrntLog.info('ModemInfo:3 5 %s 0' % count)
        return "3 5 " + count + " 0"
 
    #移动介质数量<空格>移动介质1容量<空格>移动介质 2容量<空格>
    def USBCountInfo(self):
        #TODO 此处处理了移动盘，移动介质是否还包含其他？
        (status, output) = commands.getstatusoutput('ls -l /dev/disk/by-path/*-usb-* | fgrep -v part')
        #print output
        if output == '' or re.search('ls: ', output):
            PrntLog.info('USBCountInfo:3 6 0')
            return "3 6 0"

        lines = []
        count = 0
        while '\n' in output:
            line, output = output.split('\n', 1)
            line = line.split(' -> ../../')[1]
            lines.append(line)
            count = count + 1
        output = output.split(' -> ../../')[1]
        lines.append(output)
        count = count + 1

        ret = str(count) + ' '
        for line in lines:
            with open('/proc/partitions', 'r') as dp:
                for disk in dp.readlines():
                    if re.search(line + '\n', disk):
                        blknum = disk.strip().split(' ')[-2]
                        ret = ret + str(round(float(blknum)/1024/1024, 2)) + ' '
        PrntLog.info('USBCountInfo:3 6 %s' % ret)
        return "3 6 "+ ret

    #串口数量
    def SerialCount(self):
        (status, count ) = commands.getstatusoutput('cat /proc/tty/driver/serial |grep -v "unknown" | wc -l')
        string = str(int(count)-1)
        PrntLog.info('SerialCount:3 7 %s' % string )
        return "3 7 " + string
 
    #并口数量
    def ParaCount(self):
        (status, dd ) = commands.getstatusoutput('ls /dev/lp*')
        list = dd.split('\n')
        count = 0
        for lp in list:
            (result, tmp) = commands.getstatusoutput('echo "test" >' + lp)
            if result == 0:
                count = count+1
        PrntLog.info('ParaCount:3 8 %s' % str(count) )
        return "3 8 " + str(count)
 
    #网卡数量<空格>网卡1名称<空格>网卡1速率类型<空格>网卡2名称<空格>网卡2速率类型……
    def ethInfo(self):
        key_info = psutil.net_io_counters(pernic=True).keys()  # 获取网卡名称
        count = 0
        re = ""
 
        for key in key_info:
            re = re + str(key) + " " #网卡名称
            (status, spped ) = commands.getstatusoutput('ethtool ' + str(key) + ' | grep Speed')
            #网卡速率
            if "10M" in spped:
                re = re+"0 "
            elif "100M" in spped:
                re = re+"1 "
            elif "1000M" in spped:
                re = re+"2 "
            else:
                re = re+"5 "
            count = count+1
        PrntLog.info('ethInfo:3 4 %s %s' % (str(count),re))
        return "3 4 " + str(count) + " "+re

    # os version information
    def OSInfo(self):
        #var=platform.dist()
        uname=platform.uname()
        #('Linux', 'nari-rhel7', '3.10.0-229.el7.x86_64', '#1 SMP Thu Jan 29 18:37:38 EST 2015', 'x86_64', 'x86_64')
        ostye = "2"
        '''
        with open('/etc/issue', 'r') as dp:
            for line in dp.readlines():
                type = line.strip().split(' ')[0]
                break

        #TODO 凝思版本号是啥？
        if "Linx" in type:
            osversion = "0"
        elif "Kylin" in type:
            osversion = "1"
            num = line.strip().split(' ')[2]
        else:
            osversion = "2"
            num = line.strip().split(' ')[-2]
        '''
        PrntLog.info('OSInfo:3 10 %s %s %s' % (ostye, str(os_version["version"]),uname[2]) )
        return "3 10 " + ostye + " "+str(os_version["version"]) + " "+ uname[2]
