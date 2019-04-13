#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
@date: 20167-06-15
@author: qilongyun
'''

import struct
import socket
import os
from utilsCommon import PrntLog
from utilsCommon import get_cuurent_time

class MsgWrap(object):
    def __init__(self,LinkInfo,itemDict=None):
        self.LinkInfo = LinkInfo
        self.itemDict= itemDict

    #SSH A->B   B机发送报文
    def Msg_SSH_Server_Data(self):
        msgType = 0
        upSSHLink=struct.pack('<18s','')
        locaSSHlLink = struct.pack( '<4sH4sQ',
                                    covert_ipaddr(self.LinkInfo['CLIENT_IP']),
                                    int(self.LinkInfo['CLIENT_PORT']),
                                    covert_ipaddr(self.LinkInfo['LOCAL_IP']),
                                    int(self.LinkInfo['time'].replace( '_', '' )[:-3]))
        upX11Link = struct.pack( '<18s', '' )

        strMsg =  struct.pack('<B18s18s18sI256s',msgType,upSSHLink,locaSSHlLink,upX11Link,
                           int(self.LinkInfo['PID_NUM']),self.LinkInfo['USER_NAME'])
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    #SSH/X11  A->B->C  or X->B->C   B机发送报文
    def Msg_SSH_Client_Data(self):
        msgType = 0
        if self.LinkInfo['LOGIN_TYPE'] == 'ssh':
            upSSHLink = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                    int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                    int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        else:
            upSSHLink = struct.pack( '<18s', '' )

        locaSSHlLink = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['FORWARD_PORT'] ), covert_ipaddr( self.LinkInfo['REMOTE_IP'] ),
                              int( self.LinkInfo['REMOTE_DT'].replace( '_', '' )[:-3] ) )

        if self.LinkInfo['LOGIN_TYPE'] == 'x11':
            upX11Link = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                     int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                     int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        else:
            upX11Link = struct.pack( '<18s', '' )

        strMsg = struct.pack( '<B18s18s18s4s256s', msgType, upSSHLink, locaSSHlLink, upX11Link,'','')

        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    #回显报文处理
    def Msg_Echo_DATA(self, strLine):
        try:
            if self.LinkInfo['LOGIN_TYPE'] == 'ssh':
                return self.Msg_SSH_Echo_DATA(strLine )
            elif self.LinkInfo['LOGIN_TYPE'] == 'x11':
                return self.Msg_X11_Echo_DATA(strLine)
            elif self.LinkInfo['LOGIN_TYPE'] == 'local':
                return self.Msg_LOCAL_Echo_DATA( strLine )
        except Exception as e:
            PrntLog.error( 'Failed Msg_Echo_DATA: %s  (Error:%s) ' % (strLine, e) )

    def Msg_SSH_Echo_DATA(self,strLine):
        msgType = 0x03
        locaSSHlLink = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                    int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                    int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        currentTime = get_cuurent_time()
        echotime = int( currentTime.replace( '_', '' )[:-3] )
        strLen=len(strLine)
        strFormt='<B18sQI%ds' % strLen
        strMsg = struct.pack(strFormt, msgType, locaSSHlLink, echotime,strLen ,strLine)
        #PrntLog.info(PrtMsg( strMsg ))
        PrntLog.info( 'send Msg_SSH_Echo_DATA')
        return strMsg

    def Msg_X11_Echo_DATA(self,strLine):
        msgType = 0x0A
        locaX11Link = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                    int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                    int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        ttyString=covert_tty(self.itemDict['TTY'])

        currentTime = get_cuurent_time()
        echotime = int( currentTime.replace( '_', '' )[:-3] )
        strLen=len(strLine)
        strFormt='<B18s32sQ32sI%ds' % strLen
        strMsg = struct.pack(strFormt, msgType, locaX11Link, ttyString,echotime,self.LinkInfo['USER_NAME'], strLen ,strLine)
        #PrntLog.info(PrtMsg( strMsg ))
        PrntLog.info( 'send Msg_X11_Echo_DATA' )
        return strMsg

    def Msg_LOCAL_Echo_DATA(self,strLine):
        msgType = 0x0E
        locaLink = struct.pack( '<4sQ', covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )

        ttyString=covert_tty(self.itemDict['TTY'])

        currentTime = get_cuurent_time()
        echotime = int( currentTime.replace( '_', '' )[:-3] )
        strLen=len(strLine)
        strFormt='<B12s32sQ32sI%ds' % strLen
        strMsg = struct.pack(strFormt, msgType, locaLink, ttyString,echotime,self.LinkInfo['USER_NAME'], strLen ,strLine)
        #PrntLog.info(PrtMsg( strMsg ))
        PrntLog.info( 'send Msg_LOCAL_Echo_DATA' )
        return strMsg

    # 操作报文处理
    def Msg_Cmd_DATA(self, strLine):
        try:
            if self.LinkInfo['LOGIN_TYPE'] == 'ssh':
                return self.Msg_SSH_Cmd_DATA( strLine )
            elif self.LinkInfo['LOGIN_TYPE'] == 'x11':
                return self.Msg_X11_Cmd_DATA( strLine )
            elif self.LinkInfo['LOGIN_TYPE'] == 'local':
                return self.Msg_LOCAL_Cmd_DATA( strLine )
        except Exception as e:
            PrntLog.error('Failed Msg_Cmd_DATA: %s  (Error:%s) '%(strLine,e))

    def Msg_SSH_Cmd_DATA(self,strLine):
        #1498156059_134549000###nari###/home/nari### 1002 ls -al
        msgType = 0x06
        locaSSHlLink = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                    int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                    int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        strList=strLine.split('###')
        cmdTime = int( strList[0].replace( '_', '' )[:-3] )
        cmdPath=strList[-2]
        cmdLineList=strList[-1].split(' ')
        if len(cmdLineList)<=2:
            return ''
        cmdLine=' '.join(cmdLineList[2:])
        strLen=len(cmdLine)
        strFormt='<B18sQ256sI%ds' % strLen
        strMsg = struct.pack(strFormt, msgType, locaSSHlLink, cmdTime,cmdPath,strLen ,cmdLine)
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_X11_Cmd_DATA(self,strLine):
        #1498156059_134549000###nari###/home/nari### 1002 ls -al
        msgType = 0x07
        locaX11Link = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                   int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                   int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        ttyString = covert_tty( self.itemDict['TTY'] )

        strList=strLine.split('###')
        cmdTime = int( strList[0].replace( '_', '' )[:-3] )
        cmdPath=strList[-2]
        cmdLineList = strList[-1].split( ' ' )
        if len( cmdLineList ) <= 2:
            return ''
        cmdLine = ' '.join( cmdLineList[2:] )
        strLen=len(cmdLine)
        strFormt='<B18s32sQ32s256sI%ds' % strLen
        strMsg = struct.pack(strFormt, msgType, locaX11Link,ttyString, cmdTime,self.LinkInfo['USER_NAME'],cmdPath,strLen ,cmdLine)
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_LOCAL_Cmd_DATA(self,strLine):
        #1498156059_134549000###nari###/home/nari### 1002 ls -al
        msgType = 0x0D
        locaLink = struct.pack( '<4sQ', covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        ttyString = covert_tty( self.itemDict['TTY'] )

        strList=strLine.split('###')
        cmdTime = int( strList[0].replace( '_', '' )[:-3] )
        cmdPath=strList[-2]
        cmdLineList = strList[-1].split( ' ' )
        if len( cmdLineList ) <= 2:
            return ''
        cmdLine = ' '.join( cmdLineList[2:] )
        strLen=len(cmdLine)
        strFormt='<B12s32sQ32s256sI%ds' % strLen
        strMsg = struct.pack(strFormt, msgType, locaLink,ttyString, cmdTime,self.LinkInfo['USER_NAME'],cmdPath,strLen ,cmdLine)
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_SSH_Logout_Data(self):
        msgType = 0x04
        strMsg = struct.pack( '<B4sH4sQ', msgType,covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                    int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                    int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )

        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_SSH_LogFail_Data(self):
        msgType = 0x16
        strMsg = struct.pack( '<B4sH4sQ256s', msgType,covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                    int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                    int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) ,self.LinkInfo['USER_NAME'])

        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_SSH_HeartBeat(self):
        msgType=0x05
        source_ip=self.LinkInfo['CLIENT_IP']
        source_port=int(self.LinkInfo['CLIENT_PORT'])
        local_ip=self.LinkInfo['LOCAL_IP']
        link_time=self.LinkInfo['time']

        source_addr=covert_ipaddr(source_ip)
        local_addr=covert_ipaddr(local_ip)
        time = int( link_time.replace( '_', '' )[:-3] )

        strMsg=struct.pack('<B4sH4sQ',msgType,source_addr,source_port,local_addr,time)

        PrntLog.info( PrtMsg( strMsg ) )
        return strMsg

    def Msg_X11_Login_Data(self):
        msgType = 0x09
        strMsg = struct.pack( '<B4sH4sQI32s', msgType,covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                                   int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                                   int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) ,
                                   int(self.LinkInfo['PID_NUM']),self.LinkInfo['USER_NAME'] )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_X11_Loginout_Data(self):
        msgType = 0x0B
        x11Link = struct.pack( '<4sH4sQ', covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                              int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['time'].replace( '_', '' )[:-3] ))

        currentTime = get_cuurent_time( )
        loginoutTime = int( currentTime.replace( '_', '' )[:-3] )

        strMsg = struct.pack( '<B18sQ', msgType, x11Link,loginoutTime)

        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_X11_LogFail_Data(self):
        msgType = 0x19
        strMsg = struct.pack( '<B4sH4sQ32s', msgType, covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                              int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['time'].replace( '_', '' )[:-3] ), self.LinkInfo['USER_NAME'])
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_X11_HeartBeat(self):
        msgType = 0x10
        strMsg = struct.pack( '<B4sH4sQ',msgType, covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                               int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                               int( self.LinkInfo['time'].replace( '_', '' )[:-3] ) )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    #测试： X11阻断操作
    def Msg_X11_TestStopLink(self):
        msgType = 0x1A
        idString='123456789'
        strMsg = struct.pack( '<B32s4sI', msgType,idString, covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['PID_NUM'] ) )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_SSH_TestStopLink(self):
        msgType = 0x00
        idString='123456789'
        strMsg = struct.pack( '<B32s4sI', msgType,idString, covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['PID_NUM'] ) )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_LOCAL_Login_Data(self):
        msgType = 0x0C
        strMsg = struct.pack( '<B4sQ32s',msgType, covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                               int( self.LinkInfo['time'].replace( '_', '' )[:-3] ),
                              self.LinkInfo['USER_NAME'])
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_LOCAL_Loginout_Data(self):
        msgType = 0x0F
        strMsg = struct.pack( '<B4sQQ32s',msgType, covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                               int( self.LinkInfo['time'].replace( '_', '' )[:-3] ),
                              int( get_cuurent_time().replace( '_', '' )[:-3] ),
                              self.LinkInfo['USER_NAME'])

        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_LOCAL_LogFail_Data(self):
        msgType = 0x18
        strMsg = struct.pack( '<B4sQ32s', msgType, covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['time'].replace( '_', '' )[:-3] ),
                              self.LinkInfo['USER_NAME'] )

        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_LOCAL_HeartBeat(self):
        msgType = 0x13
        strMsg = struct.pack( '<B4sQ', msgType, covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                              int( self.LinkInfo['time'].replace( '_', '' )[:-3] )  )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg


    def Msg_StopLink_Res_DATA(self):
        if self.LinkInfo['LOGIN_TYPE'] == 'ssh':
            msgType = 0x08
        elif self.LinkInfo['LOGIN_TYPE'] == 'x11':
            msgType = 0x1b
        else:
            PrntLog.error('Failed Msg_StopLink_Res_DATA: %s' %self.LinkInfo['LOGIN_TYPE'])
            return

        strMsg = struct.pack( '<B32s4sH4sQQ',msgType, self.LinkInfo['ID'],covert_ipaddr( self.LinkInfo['CLIENT_IP'] ),
                           int( self.LinkInfo['CLIENT_PORT'] ), covert_ipaddr( self.LinkInfo['LOCAL_IP'] ),
                           int( self.LinkInfo['time'].replace( '_', '' )[:-3] ),
                           int( get_cuurent_time( ).replace( '_', '' )[:-3] ))
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

#解析主站的下行命令报文
class OperMsgParser(object):
    def MsgParser(self,msgStr):
        PrntLog.info(PrtMsg( msgStr ))
        operlinkInfo = {}
        MsgType = struct.unpack( "<B", msgStr[0] )
        operlinkInfo['MsgType'] = MsgType[0]
        #ssh和x11链路阻断
        if MsgType[0] == 0x00 or MsgType[0] == 0x1A:
            ret = struct.unpack( "<B32s4sI", msgStr[:41] )
            operlinkInfo['ID'] = ret[1]
            operlinkInfo['IP'] = recovert_ipaddr(ret[2])
            operlinkInfo['PID_NUM'] = str(ret[3])
        #添加用户  修改密码
        elif MsgType[0] == 0x40 or MsgType[0] == 0x42 :
            ret = struct.unpack( "<B32s4s32s20s", msgStr[:89] )
            operlinkInfo['ID'] = ret[1]
            operlinkInfo['IP'] = recovert_ipaddr(ret[2])
            operlinkInfo['USER_NAME'] = ret[3].rstrip('\0')
            operlinkInfo['PASSWD'] = ret[4].rstrip('\0')
        #修改用户
        elif MsgType[0] == 0x47:
            ret = struct.unpack( "<B32s4s32s32s", msgStr[:101] )
            operlinkInfo['ID'] = ret[1]
            operlinkInfo['IP'] = recovert_ipaddr( ret[2] )
            operlinkInfo['USER_NAME'] = ret[3].rstrip( '\0' )
            operlinkInfo['NEW_USERNAME'] = ret[4].rstrip( '\0' )
         #删除用户
        elif MsgType[0] == 0x44:
            ret = struct.unpack( "<B32s4s32s", msgStr[:69] )
            operlinkInfo['ID'] = ret[1]
            operlinkInfo['IP'] = recovert_ipaddr( ret[2] )
            operlinkInfo['USER_NAME'] = ret[3].rstrip( '\0' )
        #获取平台创建的用户列表
        elif MsgType[0] == 0x46:
            ret = struct.unpack( "<B32s4s", msgStr[:37] )
            operlinkInfo['ID'] = ret[1]
            operlinkInfo['IP'] = recovert_ipaddr( ret[2] )
        # 基线核查 add by sunboyan start from here in 2017/6/30
        elif MsgType[0] == 0x11:
            ret = struct.unpack( "<B32s4s50sI", msgStr[:91] )
            operlinkInfo['SHELL_NAME'] = ret[1].rstrip( '\0' )
            operlinkInfo['IP'] = recovert_ipaddr( ret[2] )
            operlinkInfo['XML_NAME'] = ret[3].rstrip( '\0' )
            operlinkInfo['CHECKLIST_LEN'] = ret[4]
            msgStr_length = 91 +  operlinkInfo['CHECKLIST_LEN']
            formatString='<B32s4s50sI%ds'% operlinkInfo['CHECKLIST_LEN']
            ret_again = struct.unpack( formatString,msgStr[:msgStr_length] )
            operlinkInfo['CHECKLIST'] = ret_again[5].rstrip( '\0' )
        # 基线核查 add by sunboyan end in here in 2017/6/30
        #禁用网卡请求
        elif MsgType[0] == 0x50:
            ret = struct.unpack( "<B32s4s", msgStr[:37] )
            operlinkInfo['ID'] = ret[1]
            operlinkInfo['IP'] = recovert_ipaddr( ret[2] )

        return operlinkInfo

    def Msg_AddNewCount_Res_Data(self,info):
        msgType = 0x41
        strMsg = struct.pack( '<B32s4sB', msgType, info['ID'], covert_ipaddr( info['IP'] ),info['RESULT'])
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_ChangePasswd_Res_Data(self,info):
        msgType = 0x43
        strMsg = struct.pack( '<B32s4s32sB', msgType, info['ID'], covert_ipaddr( info['IP'] ) ,info['USER_NAME'],info['RESULT'] )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_DelAccount_Res_Data(self, info):
        msgType = 0x45
        strMsg = struct.pack( '<B32s4s32sB', msgType, info['ID'], covert_ipaddr( info['IP'] ), info['USER_NAME'],
                              info['RESULT'] )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_ChangeAccountName_Res_Data(self, info):
        msgType = 0x48
        strMsg = struct.pack( '<B32s4s32sB', msgType, info['ID'], covert_ipaddr( info['IP'] ),info['USER_NAME'], info['RESULT'] )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def Msg_getCreateAccount_Res_Data(self,info):
        msgType = 0x49
        if info['usrStingLen'] == 0:
            strMsg = struct.pack( '<B32s4sI', msgType, info['ID'], covert_ipaddr( info['IP'] ), info['usrStingLen'])
        else:
            formatString='<B32s4sI%ds'% info['usrStingLen']
            strMsg = struct.pack( formatString, msgType, info['ID'], covert_ipaddr( info['IP'] ), info['usrStingLen'],
                                  info['usrSting'] )
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    # 基线核查结果 add by sunboyan start from here in 2017/6/30
    def Msg_Shell_Excute_Result(self,info):
        msgType = 0x12
        xml_length = info['XML_LENGTH']
        if xml_length == 0:
            strMsg = struct.pack( '<Bb50sI', msgType, info['RESULT'], info['XML_NAME'], info['XML_LENGTH'] )
        else:
            formatString= '<Bb50sI%ds' % xml_length
            strMsg = struct.pack(formatString, msgType, info['RESULT'], info['XML_NAME'],
                                  info['XML_LENGTH'], info['XML_FILE'] )

        PrntLog.info( PrtMsg( strMsg ) )
        return strMsg
        # 基线核查结果 add by sunboyan end in here in 2017/6/30

    def Msg_StopNetcard_Res_Data(self,info):
        msgType = 0x51
        strMsg = struct.pack( '<B32s4sB', msgType, info['ID'], covert_ipaddr( info['IP'] ), info['RESULT'] )
        PrntLog.info( PrtMsg( strMsg ) )
        return strMsg

    def test_AddNewCount_Data(self,username):
        msgType = 0x40
        idString='abcdefghijk'
        ipString='192.168.0.91'
        usrname=username
        passwd='1qa2ws!QA@WS'
        strMsg = struct.pack( '<B32s4s32s20s', msgType, idString,covert_ipaddr(ipString),usrname,passwd)
        PrntLog.info('test_AddNewCount_Data  send: ')
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def test_ChangePasswd_Data(self):
        msgType = 0x42
        idString='abcdefghijk'
        ipString='192.168.0.91'
        usrname='test4'
        passwd='kylin.2017'
        strMsg = struct.pack( '<B32s4s32s20s', msgType, idString,covert_ipaddr(ipString),usrname,passwd)
        PrntLog.info('test_ChangePasswd_Data  send: ')
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def test_ChangeAccountName_Data(self):
        msgType = 0x47
        idString = 'abcdefghijk'
        ipString = '192.168.0.91'
        usrname = 'test4'
        newusername = 'test4-1'
        strMsg = struct.pack( '<B32s4s32s32s', msgType, idString, covert_ipaddr( ipString ), usrname, newusername )
        PrntLog.info('test_ChangeAccountName_Data  send: ')
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def test_DelAccount_Data(self):
        msgType = 0x44
        idString = 'abcdefghijk'
        ipString = '192.168.0.91'
        usrname = 'test4'
        strMsg = struct.pack( '<B32s4s32s', msgType, idString, covert_ipaddr( ipString ), usrname )
        PrntLog.info('test_DelAccount_Data  send: ')
        PrntLog.info((PrtMsg( strMsg )))
        return strMsg

    def test_getCreatAccountList_Data(self):
        msgType = 0x46
        idString = 'abcdefghijk'
        ipString = '192.168.0.91'
        strMsg = struct.pack( '<B32s4s', msgType, idString, covert_ipaddr( ipString ) )
        PrntLog.info('test_getCreatAccountList_Data  send: ')
        PrntLog.info(PrtMsg( strMsg ))
        return strMsg

    def test_BaseLineCheck(self):
        msgType = 0x11
        shellString = 'baseline.sh'
        ipString = '192.168.0.92'
        xmlname = '192.168.0.92_100'
        checkklist = '1'
        check_len = len(checkklist)
        formatString='<B32s4s50sI%ds'%check_len
        strMsg = struct.pack(formatString, msgType, shellString, covert_ipaddr( ipString ), xmlname, check_len,
                              checkklist )
        PrntLog.info('test_BaseLineCheck send: ')
        PrntLog.info( PrtMsg( strMsg ) )
        return strMsg

    def test_stopnetcard(self,ipString):
        msgType = 0x50
        idString = 'abcdefghijk'
        #ipString = '192.168.0.91'
        strMsg = struct.pack( '<B32s4s', msgType, idString, covert_ipaddr( ipString ) )
        PrntLog.info( 'test_stopnetcard  send: ' )
        PrntLog.info( PrtMsg( strMsg ) )
        return strMsg

def Ip2Int(ip):
    import struct,socket
    return struct.unpack("!I",socket.inet_aton(ip))[0]

def Int2Ip(i):
    import socket,struct
    return socket.inet_ntoa(struct.pack("!I",i))

#将字符串的IP地址，转换为主机序的pack格式的ip地址
def covert_ipaddr(ipString):
    ip_str=Int2Ip(socket.ntohl(Ip2Int(ipString)))
    ip_addr = socket.inet_aton ( ip_str )
    return ip_addr

#将主机序的pack格式的ip地址 转换为字符串的IP地址
def recovert_ipaddr(packed_ip):
    ip_str=socket.inet_ntoa( packed_ip )
    ipString=Int2Ip(socket.ntohl(Ip2Int(ip_str)))
    return ipString


# pts3 ->   /dev/pts/3
# tty2 ->   /dev/tty2
def covert_tty(ttySting):
    if ttySting.find('pts') >=0:
        return '/dev/pts/'+ttySting[3:]
    elif ttySting.find('tty') >=0:
        return '/dev/'+ttySting
    else:
        return ''

def PrtMsg(s):
    b = bytearray( s )
    string=''
    for i in b:
        string=string+"%02x " % i
    return string
    #PrntLog.info(string)