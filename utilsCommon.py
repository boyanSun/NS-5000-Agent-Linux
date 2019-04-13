#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import sys, os
import socket
import time
import commands
import subprocess
from subprocess import call
from AgentLog import AgentLog
from KafkaTransfer import Kafka_producer
from KafkaTransfer import Kafka_consumer
import psutil
import ConfigParser
import platform

PrntLog=AgentLog().getLogger()

#读取配置文件信息
Config_agent = ConfigParser.ConfigParser( )
try:
    Config_agent.read('agent.conf')
except Exception as e:
    print('ConfigParser Failed: agent.conf %s '%e)
    PrntLog.error('ConfigParser Failed: agent.conf %s '%e)

def get_os_version():
    #默认值redhat 6
    osversion = {"type":"redhat", "name":"redhat", "version":6}

    try:
        (status, ret) = commands.getstatusoutput( './os_detect.sh -o' )
        output = ret.split("\n")
        for line in output:
            if "OS:" in line:
                str = line.split(":")[-1]
                if "RedHat" in line:
                    osversion["type"] = "redhat"
                    osversion["name"] = "redhat"
                elif "CentOS" in str:
                    osversion["type"] = "redhat"
                    osversion["name"] = "centos"
                elif "Debian" in line:
                    osversion["type"] = "debian"
                    osversion["name"] = "debian"
                elif "Ubuntu" in line:
                    osversion["type"] = "debian"
                    osversion["name"] = "ubuntu"
            elif "VER:" in line:
                osversion["version"] = int(line.split(":")[-1])
    except Exception as e:
        PrntLog.error( 'get_os_version Failed. ' )

    return osversion

os_version = get_os_version()
print 'os_version: ',os_version

#获取本机的所有网卡名与IP地址
def get_netcard():
    netcard_info = []
    info = psutil.net_if_addrs()
    for k,v in info.items():
        for item in v:
            if item[0] == 2 and not item[1]=='127.0.0.1':
                netcard_info.append((k,item[1]))
    return netcard_info

#根据IP获取网卡名称
def get_netname_by_ip(ipStr):
    netcard_info = get_netcard( )
    for info in netcard_info:
        if ipStr == info[1]:
            return info[0]
    return False

#判断IP是否为本机IP
def judge_ip_localhost(ipStr):
    netcard_info= get_netcard()
    for info in netcard_info:
        if ipStr==info[1]:
            return True
    return False

def get_kafka_ip_port_config():
    try:
        kafka_IP = Config_agent.get( 'kafka_config' ,'kafka_IP')
        kafka_PORT = Config_agent.getint( 'kafka_config', 'kafka_PORT' )
        host_ip = Config_agent.get( 'kafka_config', 'host_ip' )
    except Exception as e:
        PrntLog.error( 'get_kafka_ip_port_config  Failed. ' )
        raise Exception( 'get_kafka_ip_port_config Failed.' )

    if kafka_IP == '' or host_ip == '':
        raise Exception( 'kafka_IP or host_ip has not been configed. Please check agent.conf !' )

    if not judge_ip_localhost( host_ip ):
        raise Exception( 'host_ip is not local host ip. Please check agent.conf !' )

    return (kafka_IP, kafka_PORT, host_ip)

(kafka_IP, kafka_PORT,host_ip) =get_kafka_ip_port_config()
gHost_ip=host_ip
print('kafka_IP = %s kafka_PORT=%d host_ip=%s '%(kafka_IP, kafka_PORT,host_ip))
PrntLog.info ('kafka_IP = %s kafka_PORT=%d host_ip=%s '%(kafka_IP, kafka_PORT,host_ip))

#pf_oper = Kafka_producer("172.16.140.252", 9092, "pf_oper")
pf_oper = Kafka_producer(kafka_IP, kafka_PORT, "pf_oper")
pf_monitor = Kafka_producer(kafka_IP, kafka_PORT, "pf_monitor")
pf_warn = Kafka_producer(kafka_IP, kafka_PORT, "pf_warn")
pf_base = Kafka_producer(kafka_IP, kafka_PORT, "pf_base")

#获取当前时间
def get_cuurent_time():
    try:
        fp=os.popen( 'date +"%s_%N"' )
        for str in fp:
            fp.close()
            timestr=str.rstrip('\n')
            return timestr
    except Exception as e:
        PrntLog.error( 'Failed get_cuurent_time : %s' % e )

#获取本机IP地址 根据配置IP来返回
def get_host_ip():
    global gHost_ip
    return gHost_ip
    try:
        ret = os.popen(
            "LANG=C /usr/local/sagent-3000-ns/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'" )
        ipaddr=''
        for str in ret:
            ipaddr= str.lstrip( 'addr:' ).rstrip('\n')
        ret.close()
        if ipaddr!='':
            return ipaddr
        else:
            return '127.0.0.1'
    except Exception as e:
        PrntLog.error('Failed get_host_ip : %s'%e)
        return '127.0.0.1'

def get_groupid_for_consumer():
    return get_host_ip()+get_cuurent_time()

#sys_oper = Kafka_consumer( kafka_IP, kafka_PORT, "pf_oper", get_groupid_for_consumer())
sys_oper = Kafka_consumer( kafka_IP, kafka_PORT, "sys_oper", get_groupid_for_consumer())
sys_base= Kafka_consumer( kafka_IP, kafka_PORT, "sys_base", get_groupid_for_consumer())

'''
def get_ip_address(ifname='eth0'):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except:
        ips = os.popen(
            "LANG=C /sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'").readline().rstrip(
            '\n')

        if len(ips) > 0:
            return ips.lstrip('addr:')
    return ''
'''

def get_prefix():
    (status, time) = commands.getstatusoutput('date "+%Y-%m-%d %H:%M:%S"')
    (status, hostname) = commands.getstatusoutput('hostname')
    ipadd = get_host_ip()
    return str(time) + " " + ipadd + "#" + hostname + " SVR"


#获取Listen端口白名单配置
def get_hardware_thresholdvalue():
    Config_agent.remove_section('hardware_thresholdvalue')
    Config_agent.read( 'agent.conf' )

    try:
        configList = Config_agent.items( 'hardware_thresholdvalue' )
    except Exception as e:
        PrntLog.error('get_hardware_thresholdvalue get threshold Failed. ')
        #raise Exception( 'get_white_port_list get white port list Failed.' )
    tempvalue=100
    fanvalue=0
    for info in configList:
        if 'tempvalue' == info[0]:
            tempvalue= float(info[1])
        if 'fanvalue' == info[0]:
            fanvalue = float(info[1])

    PrntLog.info('get_hardware_thresholdvalue tempvalue:%s  fanvalue:%s '%(tempvalue,fanvalue))
    return (tempvalue,fanvalue)