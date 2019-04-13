#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import sys, os
import time
import commands
from AgentLog import AgentLog
import psutil
from datetime import datetime

PrntLog=AgentLog().getLogger()

class auditOper():
    @staticmethod
    def make_start_time(secs):
        start_time = datetime.fromtimestamp(time.time() - secs).strftime("%m/%d/%Y %H:%M:%S")
        return start_time

    @staticmethod
    def add_audit_to_execve():
        #不使用时直接返回
        return
        # 配置审计规则
        cmd = "auditctl -a exit,always -F arch=b64 -F euid=0 -S execve -k root-commands"
        (status, ret) = commands.getstatusoutput(cmd)
        #print ("audit_command_execve cmd[%s],status[%d],ret[%s]" % (cmd, status, ret))
        cmd = "auditctl -a exit,always -F arch=b32 -F euid=0 -S execve -k root-commands"
        (status, ret) = commands.getstatusoutput(cmd)
        #print ("audit_command_execve cmd[%s],status[%d],ret[%s]" % (cmd, status, ret))

    @staticmethod
    def add_audit_to_file(filepath, rules="rwax"):
        #不使用时直接返回
        return
        cmd = "auditctl -w " + filepath + " -p " + rules + " -k filechange"
        (status, ret) = commands.getstatusoutput(cmd)
        #print ("add_audit_to_file cmd[%s],status[%d],ret[%s]"%(cmd,status,ret))

    @staticmethod
    def get_file_owner(filepath):
        # 不能找到用户时，先查找文件所有者，若失败，则给定root
        try:
            from os import stat
            from pwd import getpwuid
            usrname = getpwuid(stat(filepath).st_uid).pw_name
            return usrname
        except:
            return "root"

    @staticmethod
    def get_file_change_usrname(filepath):
        #不使用时直接返回文件所有者
        return auditOper.get_file_owner(filepath)
        try:
            #仅查找20s内的日志
            start_time = auditOper.make_start_time(20)
            cmd = "ausearch -f " + filepath.split("/")[-1] + " -ts " + start_time + " -k filechange -i | grep type=SYSCALL | tail -n 1"
            (status, ret) = commands.getstatusoutput(cmd)
            #print ("get_file_change_usrname cmd[%s],status[%d],ret[%s]"%(cmd,status,ret))
            if "<no matches>" in ret:
                return auditOper.get_file_owner(filepath)

            usrname=ret.split(" uid=")[-1].split()[0]
            return usrname
        except:
            return auditOper.get_file_owner(filepath)

    @staticmethod
    def parse_one_log(log):
        log_time = log.split("msg=audit(")[-1].split(") : ")[0]
        pid = log.split(" pid=")[-1].split()[0]
        ppid = log.split(" ppid=")[-1].split()[0]
        exe = log.split(" exe=")[-1].split()[0]
        return {"log_time":log_time, "pid":pid, "ppid":ppid, "exe":exe}

    @staticmethod
    def get_caller_info(pid,name):
        exe = ""
        ppid = ""
        # 先从proc中查找此进程
        if int(pid) in psutil.pids():
            (status, exe) = commands.getstatusoutput('readlink -f /proc/' + pid + '/exe')
            if pid != "1":
                ppid = str(psutil.Process(int(pid)).ppid())

        # proc中未找到，根据pid查找最新的一条日志信息，不能指定时间段
        if exe == "":
            cmd = "ausearch -sc execve -p " + pid + " -k root-commands -i | tail -n 1"
            (status, ret) = commands.getstatusoutput(cmd)
            #print ("get_caller_info cmd[%s],status[%d],ret[%s]"%(cmd,status,ret))
            #日志中未能找到
            if "<no matches>" in ret:
                return ""
            exe = ret.split(" exe=")[-1].split()[0]
            if pid != "1":
                ppid = ret.split(" ppid=")[-1].split()[0]

        if exe == "":
            return ""
        #跳过可能的控制终端
        if exe == "/bin/bash" \
                or exe == "/usr/bin/script" \
                or exe == "/usr/bin/gnome-terminal" \
                or ("sshd" not in name and exe == "/usr/sbin/sshd")\
                or exe == "/bin/login":
            return auditOper.get_caller_info(ppid, name)

        return {"pid":pid, "exe":exe}

    @staticmethod
    def proc_log_by_executable_name(name, start_time, looptime):
        last_time = start_time
        callerdictlist = []
        #控制查询时间
        if start_time == "":
            start_time = auditOper.make_start_time(20 + looptime)
        cmd = "ausearch -sc execve -ts " + start_time + " -x " + name + " -k root-commands -i"
        (status, ret) = commands.getstatusoutput(cmd)
        #print ("proc_log_by_executable_name cmd[%s],status[%d],ret[%s]"%(cmd,status,ret))
        if "<no matches>" in ret:
            return last_time, callerdictlist

        #处理获取的所有日志
        output = ret.split("\n")
        for line in output:
            if "type=SYSCALL" not in line:
                continue
            #exe匹配
            exe = line.split(" exe=")[-1].split()[0]
            if "/" in exe:
                exe = exe.split("/")[-1]

            if "\"" in exe:
                exe = exe.split("\"")[0]

            if name != exe:
                continue

            dict = auditOper.parse_one_log(line)
            if dict["log_time"] <= start_time:
                continue
            last_time = dict["log_time"]
            #获取调用进程信息
            callerdict = auditOper.get_caller_info(dict["ppid"],name)
            if callerdict != "":
                callerdictlist.append(callerdict)

        return last_time, callerdictlist