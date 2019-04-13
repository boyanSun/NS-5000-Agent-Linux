#!/usr/bin/env python2.7
#-*- coding:utf-8 -*-
import os
import pyinotify
import threading
import time
import commands
import threading
from ctypes import *
from utilsCommon import get_prefix
from utilsCommon import get_host_ip
from utilsCommon import pf_warn as pf_monitor
from utilsCommon import PrntLog
from auditOper import auditOper
from utilsCommon import os_version
import time
import traceback

orig_user_info = []
orig_group_info = []
orig_passwd_info=[]
orig_init=0

def get_add_users(user_info,orig_user_info):
    add_users=[]
    for info in user_info:
        flag=0
        for orig_info in orig_user_info:
            if info['user'] == orig_info['user']:
                flag=1
                break
        if flag==0:
            add_users.append(info)
    return add_users

def get_del_users(user_info,orig_user_info):
    del_users=[]
    for orig_info in orig_user_info:
        flag=0
        for info in user_info:
            if info['user'] == orig_info['user']:
                flag=1
                break
        if flag==0:
            del_users.append(orig_info)
    return del_users

def get_user_name():
    username = auditOper.get_file_change_usrname("/etc/shadow")
    if username == "":
        username = auditOper.get_file_change_usrname("/etc/passwd")
    if username == "":
        username = "root"
        print "user_info failed to get username, use default..."
    username = " " + username + " "
    return username

def user_info(path=""):
    global orig_init
    global orig_user_info
    global orig_group_info
    global orig_passwd_info

    if orig_init == 0 or "/etc/group" in path:
        username = get_user_name()
        time.sleep(0.2)
        #print "1-%s"%path
        group_info = []
        (status, serial) = commands.getstatusoutput('cat /etc/group | awk -F":" \'{ print $1" "$2" "$3" "$4}\'')
        list = serial.split('\n')
        for line in list:
            item = line.split(' ')
            info = {}
            info['name'] = item[0]
            info['gid'] = item[2]
            mem = []
            if len(item) == 4:
                mem = item[3].split(",")
            info['mem'] = mem
            group_info.append(info)

        if orig_init == 0:
            orig_group_info = group_info[:]

        if orig_init != 0:
            if len(orig_group_info) != len(group_info):
                orig_group_info = group_info
                return
            if orig_group_info != group_info:
                for i in range(0, len(group_info)):
                    flag = 0
                    if group_info[i]["name"] == "root" or group_info[i]["name"] == "test":
                        flag = 0
                    if flag == 1:
                        print "new:",group_info[i],"old:",orig_group_info[i]
                    if group_info[i]["mem"] == orig_group_info[i]["mem"]:
                        if flag == 1:
                            print "2-continue"
                        continue
                    for m in group_info[i]["mem"]:
                        if m not in orig_group_info[i]["mem"] and m != "":
                            strMsg = "<2> " + get_prefix() + " 5 35 " + get_host_ip() + \
                                     username + m + ' change group to '+ group_info[i]["name"]
                            pf_monitor.sendmsg(strMsg)
                            PrntLog.info('user_perm_change: %s' % strMsg)

                orig_group_info = group_info
                return

    time.sleep(0.2)

    user_info=[]
    (status, serial) = commands.getstatusoutput('cat /etc/passwd | awk -F":" \'{ print $1" "$2" "$3" "$4}\'')
    list = serial.split('\n')
    for line in list:
        item = line.split(' ')
        info={}
        info['user']=item[0]
        info['id']=item[2]
        info['gid'] = item[0]
        gid=item[3]
        for gg in orig_group_info:
            if gg["gid"] == gid:
                info['gid'] = gg["name"]
                break
        user_info.append(info)

    passwd_info=[]
    (status, serial) = commands.getstatusoutput('cat /etc/shadow | awk -F":" \'{ print $1" "$2}\'')
    list = serial.split('\n')
    for line in list:
        item = line.split(' ')
        info={}
        info['user']=item[0]
        info['passwd']=item[1]
        passwd_info.append(info)

    if orig_init == 0:
        auditOper.add_audit_to_file("/etc/shadow", "wx")
        auditOper.add_audit_to_file("/etc/passwd", "wx")
        orig_user_info=user_info[:]
        orig_passwd_info=passwd_info[:]
        orig_init = 1

    #add_users=[ i for i in user_info if i not in orig_user_info]
    #del_users=[ i for i in orig_user_info if i not in user_info]

    # 用组ID发生变化时，会误报增加和删除用户
    add_users = get_add_users( user_info, orig_user_info )
    del_users = get_del_users( user_info, orig_user_info )

    username = get_user_name()
    for i in add_users:
        strMsg="<2> " + get_prefix() + " 5 35 " + get_host_ip() + username + i['user'] + ' adduser ' + i['user']
        pf_monitor.sendmsg(strMsg)
        PrntLog.info('user_perm_change:%s' % strMsg)

    for i in del_users:
        strMsg="<2> " + get_prefix() + " 5 35 " + get_host_ip() + username + i['user'] + ' deluser ' + i['user']
        pf_monitor.sendmsg(strMsg)
        PrntLog.info('user_perm_change: %s' % strMsg)

    for item in orig_passwd_info:
        for ii in passwd_info:
            if item['user'] == ii['user'] and item['passwd'] <> ii['passwd']:
                strMsg="<2> " + get_prefix() + " 5 35 " + get_host_ip() + username + item['user'] + ' chpasswd ' + item['user']
                pf_monitor.sendmsg(strMsg)
                PrntLog.info('user_perm_change: %s' % strMsg)
    for item in orig_user_info:
        for ii in user_info:
            if item['user'] == ii['user'] and item['gid'] <> ii['gid']:
                strMsg="<2> " + get_prefix() + " 5 35 " + get_host_ip() + username + item['user'] + ' change group to ' +ii['gid']
                pf_monitor.sendmsg(strMsg)
                PrntLog.info('user_perm_change: %s' % strMsg)

    orig_user_info=user_info[:]
    orig_passwd_info=passwd_info[:]

class OnIOHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        PrntLog.info("user_perm_change notify %s"%event.pathname)
        try:
            user_info(event.pathname)
        except:
            PrntLog.error("user_info fail: %s" % traceback.format_exc())

def user_perm_change(perf):
    try:
        user_info()
        watchList = ['/etc/']
        wm = pyinotify.WatchManager()
        mask = pyinotify.IN_MODIFY
        #notifier = pyinotify.ThreadedNotifier(wm, OnIOHandler())
        notifier = pyinotify.Notifier( wm, OnIOHandler( ) )
        #notifier.start()
        wm.add_watch(watchList, mask, rec=True, auto_add=True)
        PrntLog.info( 'user_perm_change: Start monitoring %s' % watchList )
    except Exception as e:
        PrntLog.error('user_perm_change init failed:%s' % e)
        PrntLog.error( "user_perm_change fail: %s" % traceback.format_exc( ) )

    while True:
        try:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
        except KeyboardInterrupt:
            notifier.stop()
            break
        #except Exception as e:
        #    PrntLog.error('user_perm_change failed:%s' % e)


if __name__ == '__main__':
    user_perm_change(60)
