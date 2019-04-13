#!/usr/bin/env python
# -*- coding:utf-8 -*-
from subprocess import call

from LogParser import LogParser
from OperParser import OperParser
from StateInfo import StateInfo
from ConfigInfor import ConfigInfor
from warn import serial_info
from warn import parallel_info
from warn import net_info
from warn import warning_info
from warn import warn_check_info
from warn import proc_command_execve_log
from CriticalFilePerm import critical_file_perm_change
from UserPerm import user_perm_change
from utilsCommon import PrntLog
from utilsCommon import sys_oper
from utilsCommon import sys_base
from utilsCommon import Config_agent
from auditOper import auditOper
import os
import pyinotify
import threading
import time
import ctypes
import sys
from datetime import datetime
import commands
import hashlib
from lib_dec import dec_lib

logparser=LogParser()
config=ConfigInfor()
operpaser=OperParser()
stateInfo=StateInfo()

class OnIOHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        global g_EventListSet,mutex
        if event.maskname == 'IN_MODIFY':
            if mutex.acquire( 5 ):
                g_EventListSet.add(event.pathname)
                mutex.release( )

class inotify_log(threading.Thread):
    def __init__(self):
        threading.Thread.__init__( self )

    def run(self):
        #从agent.conf中获取文件监视列表
        watchList=[]
        try:
            configList = Config_agent.items( 'echo_cmd_watchlist' )
        except Exception as e:
            PrntLog.error( 'inotify_log get watchList Failed. ')
            raise Exception('inotify_log get watchList Failed.')

        for info in configList:
            watchList.append( info[1] )

        for strPath in watchList:
            if not os.path.exists(strPath):
                os.makedirs(strPath)
                if os.path.exists(strPath):
                    command = "chmod 777 " + strPath
                    os.system(command)
                    command = "chmod a+t " + strPath
                    os.system(command)

        wm = pyinotify.WatchManager()
        #mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_MOVED_FROM
        mask = pyinotify.IN_MODIFY
        notifier = pyinotify.ThreadedNotifier(wm, OnIOHandler())
        notifier.start()
        wm.add_watch(watchList, mask,rec = True,auto_add = True)

        PrntLog.info('cmd and echo: Start monitoring %s' % watchList)
        while True:
            #try:
                notifier.process_events()
                if notifier.check_events():
                    notifier.read_events()
            #except Exception as e:
            #    PrntLog.error('Failed inotify_log %s '%e)
            #   time.sleep(5)

class ProcessNotifyEvent(threading.Thread):
    def __init__(self):
        threading.Thread.__init__( self )

    def run(self):
        global g_EventListSet,mutexEventSet
        while True:
            try:
                if len(g_EventListSet)>0:
                    if mutexEventSet.acquire( 5 ):
                        eventpathname=g_EventListSet.pop()
                        mutexEventSet.release( )

                        filename= os.path.basename(eventpathname)
                        filepath=os.path.dirname(eventpathname)

                        if ('secure' == filename):
                            logparser.Parser_Log_Secure()
                        elif (filepath.find('/tmp/.record')>=0):
                            #prtstr = ("%s :Action modify file: %s " % (threading.current_thread().name,os.path.join( filepath, filename )))
                            #print(prtstr)
                            #PrntLog.info( prtstr )
                            logparser.Parser_Log( 'modify', filepath, filename )

                time.sleep(1)
            except Exception as e:
                PrntLog.error( 'Failed ProcessNotifyEvent %s ' % e )

class heartbeat(threading.Thread):
    def __init__(self):
        threading.Thread.__init__( self )

    def run(self):
        while True:
            time.sleep(30)
            logparser.HearBeat()

class recvMsgFromKafka(threading.Thread):
    def __init__(self):
        threading.Thread.__init__( self )

    def run(self):
        while True:
            try:
                message = sys_oper.consume_data( )
                for str in message:
                    PrntLog.info ('sys_oper Recv kafka Msg:')
                    operpaser.OperParserMsg(str.value)
            except Exception as e:
                PrntLog.error('Failed recvMsgFromKafka %s '%e)
                time.sleep(5)

class recvBaseCheckMsgFromKafka(threading.Thread):
    def __init__(self):
        threading.Thread.__init__( self )

    def run(self):
        while True:
            try:
                message = sys_base.consume_data( )
                for str in message:
                    PrntLog.info ('sys_base Recv kafka Msg:')
                    operpaser.OperParserMsg(str.value)
            except Exception as e:
                PrntLog.error('Failed recvBaseCheckMsgFromKafka %s '%e)
                time.sleep(5)

def get_md5(file_path):  
    md5 = None  
    if os.path.isfile(file_path):  
        f = open(file_path,'rb')  
        md5_obj = hashlib.md5()  
        md5_obj.update(f.read())  
        hash_code = md5_obj.hexdigest()  
        f.close()  
        md5 = str(hash_code).lower()  
    return md5

def self_exit():
    str = "This program is not correct!"
    PrntLog.error(str)
    print str
    sys.exit(1)

def selfcheckfunc(exepath, confpath = "/etc/.sagent_hash"):
    try:
        selfok = True
        cmd = "cat %s"%confpath
        (status, ret) = commands.getstatusoutput(cmd)
        savedmd5 = ret.split()[0]
        calmd5 = get_md5(exepath)
        #print("calmd5:%s,savedmd5:%s"%(calmd5,savedmd5))
        PrntLog.warning("calmd5:%s,savedmd5:%s"%(calmd5,savedmd5))
        if savedmd5 != calmd5:
            self_exit( )
    except:
        self_exit()

    return

def config_check():
    config_md5 = get_md5("./agent.conf")
    while True:
        time.sleep(1)
        new_md5 = get_md5("./agent.conf")
        if new_md5 != config_md5:
            str = "agent.conf was modified!"
            PrntLog.warning(str)
            print str
            config_md5 = new_md5
    return

def verifyconfigfile():
    if not os.path.exists('.agent.conf'):
        PrntLog.error('config file has not been protected!')
        sys.exit( 1 )
    output = commands.getoutput( 'diff agent.conf .agent.conf')
    if output != '':
        PrntLog.error( 'config file has been illegal modified! Recover original file!' )
        output = commands.getoutput( 'rm -rf agent.conf' )
        output = commands.getoutput( 'cp .agent.conf agent.conf' )
        sys.exit( 1 )

if dec_lib("./liblicense.so", "./liclibsign") != 0:
    str = "liblicense.so is not correct!"
    PrntLog.error(str)
    print(str)
    os._exit(-1)

liblic = ctypes.cdll.LoadLibrary('./liblicense.so')
liblic.lic_check.argtypes = []
liblic.lic_check.restype = ctypes.c_void_p
liblic.freeme.argtypes = ctypes.c_void_p,
liblic.freeme.restype = None

def licsystemnotify(msg):
    commands.getoutput('grep -v "\[ns-5000-agent:\]" /etc/motd > ns.motd;mv ns.motd /etc/motd')
    if msg == '':
        return
    commands.getoutput('echo \"[ns-5000-agent:] ' + msg + '\" >> /etc/motd')
    print '[ns-5000-agent:] ' + msg
    return

def liccheckfunc():
    global liblic
    ptr = liblic.lic_check()
    ret = ctypes.cast(ptr, ctypes.c_char_p).value
    havelicense = int(ret.split(' ')[0])
    outdatetimestamp = int(ret.split(' ')[1])
    liblic.freeme(ptr)

    outdate = datetime.fromtimestamp(outdatetimestamp).strftime("%Y-%m-%d %H:%M:%S")

    if havelicense == 0:
        str = "You have not installed any license file yet!"
        PrntLog.error(str)
        print str
        licsystemnotify('')
        sys.exit(1)
    elif havelicense == 1:
        # 剩余30天开始提醒
        if outdatetimestamp < time.time():
            str = "Your license file expired in [" + outdate + "]!"
            licsystemnotify(str)
            PrntLog.error(str)
        elif (outdatetimestamp - 30 * 24 * 3600) < time.time():
            str = "Your license file will expire in [" + outdate + "]!"
            licsystemnotify(str)
            PrntLog.info(str)
        else:
            licsystemnotify('')
    return

g_EventListSet=set()
mutexEventSet=threading.Lock()
mutex = threading.Lock()

if __name__ == "__main__":
    #selfcheckfunc("/usr/local/sagent-3000-ns/sagent-3000-ns")
    #verifyconfigfile()
    liccheckfunc()

    # 配置系统调用审计
    auditOper.add_audit_to_execve()

    threads = []
    t1 = threading.Thread(target=net_info,args=(60,))
    t2 = threading.Thread(target=warning_info,args=(60,))
    t3 = threading.Thread(target=serial_info,args=(60,))
    t4 = threading.Thread(target=user_perm_change,args=(60,))
    t5= threading.Thread(target=critical_file_perm_change,args=(60,))
    t6= threading.Thread(target=warn_check_info,args=(60,))
    t7= threading.Thread(target=proc_command_execve_log,args=(2,))
    t8 = threading.Thread(target=config_check)
    t9 = threading.Thread(target=parallel_info, args=(60,))

    threads.append(t1)
    threads.append(t2)
    threads.append(t3)
    threads.append(t4)
    threads.append(t5)
    threads.append( t6 )
    #threads.append( t7 )
    #threads.append( t8 )
    threads.append(t9)
    config.report()

    #监视日志
    logparser.Init_Log_Secure_Pos()
    operpaser.init_gCreateAccountrSet()

    ProcessNotifyEvent().start()
    inotify_log().start()
    heartbeat().start()
    recvMsgFromKafka().start()
    recvBaseCheckMsgFromKafka().start()
    stateInfo.start()
    for t in threads:
        t.setDaemon(True)
        t.start()

    #软件授权检测
    while True:
        time.sleep(600)
        liccheckfunc()

    PrntLog.info("main is end!")