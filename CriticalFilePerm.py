#!/usr/bin/env python2.7
#-*- coding:utf-8 -*-
import os
import os.path
import pyinotify
import threading
import time
import commands
import threading
import multiprocessing
from ctypes import *
from utilsCommon import get_prefix
from utilsCommon import get_host_ip
from utilsCommon import pf_warn as pf_monitor
from utilsCommon import PrntLog
from utilsCommon import Config_agent
from auditOper import auditOper

AllDirDict={}
AllFileDict={}

def watch_delay_call(watchList, callback, mask, delay=0.5):
    class Process(pyinotify.ProcessEvent):
        def __init__(self, immediate_callback):
            self.immediate_callback = immediate_callback

        def process_default(self, event):
            #跳过IN_IGNORED事件,跳过无效的重复事件
            if event.maskname != "IN_IGNORED" or event.name == "":
                self.immediate_callback(event)

    def delay_call(pipe, delayed_callback, delay):
        event_list = []
        while True:
            try:
                #等待inotify事件
                event_list.append(pipe.recv())
                while pipe.poll():
                    event_list.append(pipe.recv())
                #延时
                time.sleep(delay)
                #如果还有事件，重新计时
                if pipe.poll():
                    continue
                #执行延时处理函数.
                delayed_callback(event_list)
                #清空事件列表
                event_list = []
            except:
                pass

    #构造读写PIPE
    receiver, sender = multiprocessing.Pipe(False)
    delay_callback_thread = threading.Thread(target=delay_call, args=(receiver, callback, delay))
    delay_callback_thread.daemon = True
    delay_callback_thread.start()

    while True:
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, Process(sender.send))
        wm.add_watch(watchList, mask, rec=True, auto_add=True)
        try:
            while True:
                notifier.process_events()
                if notifier.check_events():
                    notifier.read_events()
        except KeyboardInterrupt:
            notifier.stop()
            break

def report(pathname, mode, oldperm, newperm):
    username = auditOper.get_file_change_usrname(pathname)
    strings="<4> " + get_prefix() +" 5 34 " + get_host_ip() + ' ' + username + ' ' + pathname + ' ' + mode + ' ' + oldperm + ' ' + newperm
    PrntLog.info(strings)
    #print "report:",strings
    pf_monitor.sendmsg(strings)

class permOper():
    @staticmethod
    def get_perm_from_file(pathname, savetodict=False):
        global AllDirDict
        global AllFileDict
        k = ""
        if not os.path.exists(pathname):
            PrntLog.info('get_perm_from_file:%s not exists.' % pathname)
            return
        if os.path.isdir(pathname):
            k = oct(os.stat(pathname).st_mode)[3:]
            if savetodict:
                AllDirDict[pathname] = k
        elif os.path.isfile(pathname):
            k = oct(os.stat(pathname).st_mode)[4:]
            if savetodict:
                AllFileDict[pathname] = k
        return k

    @staticmethod
    def delete(pathname):
        global AllDirDict
        global AllFileDict
        if pathname in AllDirDict.keys():
            del AllDirDict[pathname]
        elif pathname in AllFileDict.keys():
            del AllFileDict[pathname]

    @staticmethod
    def get_perm_from_dict(pathname):
        if pathname in AllDirDict.keys():
            return AllDirDict[pathname]
        elif pathname in AllFileDict.keys():
            return AllFileDict[pathname]

        return ""

def report_filter(list, mode):
    if len(list) == 1:
        item = list[0]
        report(item["pathname"], mode, item["oldperm"], item["newperm"])
        return
    #排序
    newlist = sorted(list, key=lambda k: k['pathname'])

    #只报一级目录
    rootlevel = 0
    rootpath = ""
    for item in newlist:
        if rootlevel != 0 and rootpath in item["pathname"]:
            if item["pathname"].count("/") - rootlevel < 2:
                report(item["pathname"], mode, item["oldperm"], item["newperm"])
        else:
            rootlevel = item["pathname"].count("/")
            rootpath = item["pathname"]
            report(item["pathname"], mode, item["oldperm"], item["newperm"])

    return

def delay_callback(event_list):
    #print event_list
    del_list = []
    perm_change_list = []

    #inotify事件分发处理
    for event in event_list:
        if "IN_MODIFY" in event.maskname:
            report(event.pathname, '1', '0', '0')
        if "IN_MOVED_FROM" in event.maskname:
            report( event.pathname, '2', '0', '0' )
            permOper.delete(event.pathname)
        if "IN_MOVED_TO" in event.maskname or "IN_CREATE" in event.maskname:
            report( event.pathname, '0', '0', '0' )
            permOper.get_perm_from_file(event.pathname, True)
        if "IN_DELETE" in event.maskname:
            permOper.delete(event.pathname)
            #保存到删除文件链表
            item = {"pathname": event.pathname, "oldperm": "0", "newperm": "0"}
            del_list.append(item)
        if "IN_ATTRIB" in event.maskname:
            if not os.path.exists(event.pathname):
                PrntLog.info( 'delay_callback:%s not exists.' % event.pathname )
                continue
            oldperm = permOper.get_perm_from_dict(event.pathname)
            newperm = permOper.get_perm_from_file(event.pathname)
            if oldperm != newperm:
                permOper.get_perm_from_file(event.pathname, True)
                #保存到文件变更链表
                item = {"pathname":event.pathname, "oldperm":oldperm, "newperm":newperm}
                perm_change_list.append(item)

    #处理文件删除和权限变更消息上报
    if len(del_list) > 0:
        report_filter(del_list, "2")

    if len(perm_change_list) > 0:
        report_filter(perm_change_list, "3")

    return

def critical_file_perm_change(perf):
    try:
        global AllDirDict
        global AllFileDict
        watchList = []
        try:
            configList = Config_agent.items( 'critical_file_list' )
        except Exception as e:
            PrntLog.error( 'critical_file_perm_change get watchList Failed. ' )
            raise Exception( 'critical_file_perm_change get watchList Failed.' )

        for info in configList:
            #对监控文件添加审计规则
            auditOper.add_audit_to_file(info[1])
            watchList.append( info[1] )

        #add by sunboyan 2017/8/17
        (AllDirDict,AllFileDict) = getWatchListDict(watchList)

        mask = pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB | pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO | pyinotify.IN_CREATE | pyinotify.IN_DELETE
        watch_delay_call(watchList, delay_callback, mask)

    except Exception as e:
        PrntLog.error('critical_file_perm_change init failed:%s' % e)

# add by sunboyan 2017/8/17
def getSingleDict(rootdir):
    list_dir = {}
    list_file = {}
    for parent,dirnames,filenames in os.walk(rootdir):
        for dirname in dirnames:
            try:
                String = parent + "/" + dirname
                m = oct(os.stat(String).st_mode)[3:]
                list_dir[String] = m
            except:
                continue
        for filename in filenames:
            try:
                file_index = os.path.join(parent,filename)
                n = oct(os.stat(file_index).st_mode)[4:]
                list_file[file_index] = n
            except:
                continue
    return list_dir,list_file

def getWatchListDict(watchlist):
    DirDict = {}
    FileDict = {}
    for index in range(0,len(watchlist)):
        (dict1,dict2) = getSingleDict(watchlist[index])
        DirDict = dict(DirDict.items() + dict1.items())
        FileDict = dict(FileDict.items() + dict2.items())
    return DirDict,FileDict
		
if __name__ == '__main__':
    critical_file_perm_change(60)
