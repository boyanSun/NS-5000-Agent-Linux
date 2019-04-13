#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
@date: 20167-06-15
@author: qilongyun
'''

from MsgWrap import OperMsgParser
from LogParser import LogParser
from utilsCommon import pf_oper
from utilsCommon import pf_base
from utilsCommon import PrntLog
from utilsCommon import judge_ip_localhost
from utilsCommon import get_netcard
import os
import crypt
import random,string
import threading
import traceback

opermsgpaser=OperMsgParser()
logparser=LogParser()
gCreateAccountrSet=set()

class OperParser(object):
    def init_gCreateAccountrSet(self):
        ret = os.path.exists('AddUserList.conf')
        if ret:
            global gCreateAccountrSet
            file = open('AddUserList.conf', 'r')
            for line in file.readlines():
                gCreateAccountrSet.add(line.rstrip('\n'))
            file.close()
    def OperParserMsg(self,str):
        try:
            operlinkInfo=opermsgpaser.MsgParser(str)
        except Exception as e:
            PrntLog.error('OperParser Failed: %s'%e)
            return

        try:
            #检查消息是否属于本主机
            if not operlinkInfo.has_key('IP') :
                return
            if not judge_ip_localhost(operlinkInfo['IP']):
                PrntLog.info(
                    'It is not own command.return. operlinkIp=%s' % (operlinkInfo['IP']) )
                return

            PrntLog.info('%s'%operlinkInfo)
            #阻断链路
            if operlinkInfo['MsgType'] == 0x00 or operlinkInfo['MsgType'] == 0x1A:
                logparser.stopLinkAndSendRes(operlinkInfo)

            #增加用户
            elif operlinkInfo['MsgType'] == 0x40:
                self.AddNewAccount(operlinkInfo)

            #修改密码
            elif operlinkInfo['MsgType'] == 0x42:
                self.ChangePasswd( operlinkInfo )

            #修改用户名
            elif operlinkInfo['MsgType'] == 0x47:
                self.ChangeAccountName( operlinkInfo )
            #删除用户
            elif  operlinkInfo['MsgType'] == 0x44:
                self.DelAccount(operlinkInfo)
            #获取平台创建的用户列表
            elif operlinkInfo['MsgType'] == 0x46:
                self.getCreateAccountList(operlinkInfo)

            # 基线核查
            elif operlinkInfo['MsgType'] == 0x11:
                self.BaseLineCheck( operlinkInfo )
            #禁用网卡
            elif operlinkInfo['MsgType'] == 0x50:
                #启动线程阻断网卡，并sleep 5，以保证kafka消费此条消息
                threading.Thread( target=stopnetcard, args=(operlinkInfo,) ).start()
        except Exception as e:
            PrntLog.error('Failed OperParser %s'%e)
            PrntLog.error("OperParser fail: %s" % traceback.format_exc())


    def AddNewAccount(self,info):
        resInfo={}
        resInfo['ID'] = info['ID']
        resInfo['IP'] = info['IP']

        cmdline='useradd %s'% info['USER_NAME']
        ret=os.system(cmdline)
        ret >>=8

        if ret == 9:
            #用户已存在
            resInfo['RESULT'] = 1
            strMsg=opermsgpaser.Msg_AddNewCount_Res_Data(resInfo)
            pf_oper.sendmsg( strMsg )
            PrntLog.error('user %s  already exists' % info['USER_NAME'])
            return
        elif ret != 0:
            #其他错误
            resInfo['RESULT'] = 2
            strMsg = opermsgpaser.Msg_AddNewCount_Res_Data( resInfo )
            pf_oper.sendmsg( strMsg )
            PrntLog.error('useradd %s unkown error!'% info['USER_NAME'])
            return

        #设置密码
        salt = getsalt( )
        passwd = crypt.crypt(info['PASSWD'] , salt )
        cmdline='usermod -p %s %s' %(passwd,info['USER_NAME'])
        ret = os.system( cmdline )
        ret >>=8

        if ret==0:
            #成功
            resInfo['RESULT'] = 0
            global gCreateAccountrSet
            gCreateAccountrSet.add(info['USER_NAME'])
            userListTofile()
            PrntLog.info( 'Msg_AddNewCount_Res_Data %s ' % resInfo )
            strMsg = opermsgpaser.Msg_AddNewCount_Res_Data( resInfo )
            pf_oper.sendmsg( strMsg )
            PrntLog.info('user %s add successful'% info['USER_NAME'])
            return
        else:
            resInfo['RESULT'] = 2
            PrntLog.info( 'Msg_AddNewCount_Res_Data %s ' % resInfo )
            strMsg = opermsgpaser.Msg_AddNewCount_Res_Data( resInfo )
            pf_oper.sendmsg( strMsg )
            PrntLog.error ('user %s set passwd failed '% info['USER_NAME'])
            return

    def ChangePasswd(self,info):
        resInfo = {}
        resInfo['ID'] = info['ID']
        resInfo['IP'] = info['IP']
        resInfo['USER_NAME'] = info['USER_NAME']

        salt = getsalt( )
        passwd = crypt.crypt( info['PASSWD'], salt )
        cmdline = 'usermod -p %s %s' % (passwd, info['USER_NAME'])
        ret = os.system( cmdline )
        ret >>= 8

        if ret == 0:
            resInfo['RESULT'] = 0
            PrntLog.info ('user %s change passwd successful '% info['USER_NAME'])
        elif ret == 6:
            # 用户不存在
            resInfo['RESULT'] = 1
            PrntLog.error ('user %s dose not exists '% info['USER_NAME'])
        else:
            resInfo['RESULT'] = 2
        PrntLog.info( 'Msg_ChangePasswd_Res_Data %s ' % resInfo )
        strMsg = opermsgpaser.Msg_ChangePasswd_Res_Data( resInfo )
        pf_oper.sendmsg( strMsg )
        return

    def ChangeAccountName(self,info):
        resInfo = {}
        resInfo['ID'] = info['ID']
        resInfo['IP'] = info['IP']
        resInfo['USER_NAME'] = info['NEW_USERNAME']

        cmdline = 'usermod -l %s %s' % (info['NEW_USERNAME'],info['USER_NAME'])
        ret = os.system( cmdline )
        ret >>= 8

        if ret == 0:
            resInfo['RESULT'] = 0
            global gCreateAccountrSet
            gCreateAccountrSet.remove( info['USER_NAME'] )
            gCreateAccountrSet.add( info['NEW_USERNAME'] )
            userListTofile()
            PrntLog.info ('change account name %s to %s successful '%(info['USER_NAME'],info['NEW_USERNAME']))
        elif ret == 6:
            # 用户不存在
            resInfo['RESULT'] = 1
            PrntLog.error ('user %s dose not exists '% info['USER_NAME'])
        elif ret == 9:
            # 用户已存在
            resInfo['RESULT'] = 2
            PrntLog.error ('user %s already exists '% info['NEW_USERNAME'])
        else:
            resInfo['RESULT'] = 3
        PrntLog.info( 'Msg_ChangeAccountName_Res_Data %s ' % resInfo )
        strMsg = opermsgpaser.Msg_ChangeAccountName_Res_Data( resInfo )
        pf_oper.sendmsg( strMsg )
        return

    def DelAccount(self,info):
        resInfo = {}
        resInfo['ID'] = info['ID']
        resInfo['IP'] = info['IP']
        resInfo['USER_NAME'] = info['USER_NAME']

        cmdline = 'userdel %s' % ( info['USER_NAME'])
        ret = os.system( cmdline )
        ret >>= 8

        if ret == 0:
            resInfo['RESULT'] = 0
            global gCreateAccountrSet
            gCreateAccountrSet.remove( info['USER_NAME'] )
            userListTofile()
            PrntLog.info ('Del account %s successful '%info['USER_NAME'] )
        elif ret == 6:
            # 用户不存在
            resInfo['RESULT'] = 1
            PrntLog.error ('Del account :user %s dose not exists '%info['USER_NAME'])
        else:
            resInfo['RESULT'] = 2
        PrntLog.info( 'Msg_DelAccount_Res_Data %s ' % resInfo )
        strMsg = opermsgpaser.Msg_DelAccount_Res_Data( resInfo )
        pf_oper.sendmsg( strMsg )
        return

    def getCreateAccountList(self,info):
        resInfo = {}
        resInfo['ID'] = info['ID']
        resInfo['IP'] = info['IP']
        usrSting=''
        global gCreateAccountrSet
        for user in gCreateAccountrSet:
            usrSting=usrSting+user+','
        #去掉最后的逗号
        usrSting=usrSting[:-1]

        resInfo['usrStingLen'] = len(usrSting)
        resInfo['usrSting'] = usrSting
        PrntLog.info('Msg_getCreateAccount_Res_Data %s '%resInfo)
        strMsg = opermsgpaser.Msg_getCreateAccount_Res_Data( resInfo )
        pf_oper.sendmsg( strMsg )
        return

    def BaseLineCheck(self, info):
        resInfo = {}
        if '.xml' in info['XML_NAME']:
            info['XML_NAME'] = info['XML_NAME'].rstrip('.xml')
        resInfo['XML_NAME'] = info['XML_NAME']
        cmdline = 'bash %s %s %s %s' % ( info['SHELL_NAME'], info['IP'], info['CHECKLIST'], info['XML_NAME'])
        PrntLog.info('BaseLineCheck cmdline=%s'%cmdline)
        ret = os.system( cmdline )
        ret >>= 8

        if ret == 0:
            resInfo['RESULT'] = 0
            PrntLog.info ('excute baseline check successful!')
        elif ret == 127:
            resInfo['RESULT'] = -1
            PrntLog.error ('no such shell file')
        elif ret == 2:
            resInfo['RESULT'] = -2
            PrntLog.error ('shell excute failed')
        else:
            resInfo['RESULT'] = -3
            PrntLog.error ('shell excute failed because of other causes ')

        # 获取xml文件大小
        resInfo['XML_FILE'] = ''
        filename = r'/tmp/%s.xml' % info['XML_NAME']
        if  ret == 0 and os.path.exists( filename ):
            # 读取文件内容
            f = open( filename, 'r' )
            for strline in f.readlines( ):
                resInfo['XML_FILE']=resInfo['XML_FILE']+strline
            f.close()
            resInfo['XML_LENGTH']=len(resInfo['XML_FILE'])
        else:
            resInfo['XML_LENGTH'] = 0
            PrntLog.error ('Failed BaseLineCheck')

        PrntLog.info('BaseLineCheck resInfo: %s'%resInfo)
        strMsg = opermsgpaser.Msg_Shell_Excute_Result( resInfo )
        pf_base.sendmsg( strMsg )
        return

def stopnetcard(info):
    import time
    time.sleep(5)
    PrntLog.info( 'stopnetcard :%s' % info )
    resInfo = {}
    resInfo['ID'] = info['ID']
    resInfo['IP'] = info['IP']

    netcard_info=get_netcard()
    for netinfo in netcard_info:
        cmdline = 'ifdown %s' % (netinfo[0])
        ret = os.system( cmdline )
        ret >>= 8
        if ret != 0:
            resInfo['RESULT'] = 0
            PrntLog.error( 'stopnetcard failed!  %s %s ' % (netinfo[0], netinfo[1]) )
            strMsg = opermsgpaser.Msg_StopNetcard_Res_Data( resInfo )
            pf_oper.sendmsg( strMsg )
        else:
            PrntLog.info( 'stopnetcard sucessful!  %s %s ' % (netinfo[0], netinfo[1]) )

    return

#加盐
def getsalt(chars = string.letters+string.digits):
    return random.choice(chars)+random.choice(chars)

#用户写入文件
def userListTofile():
    global gCreateAccountrSet
    file_object = open('AddUserList.conf', 'w')
    for user in gCreateAccountrSet:
        file_object.write(user)
        file_object.write('\n')
    file_object.close()

