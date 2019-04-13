#!/usr/bin/env python
# -*- coding:utf-8 -*-

"@date: 20167-06-15"
"@author: qilongyun"

from MsgWrap import MsgWrap
from MsgWrap import OperMsgParser
from utilsCommon import pf_oper
from utilsCommon import PrntLog
from utilsCommon import get_host_ip
from utilsCommon import get_cuurent_time
from utilsCommon import os_version
from warn import proc_failed_login
import commands
import os
import time
import traceback
gLinkList=[]
g_POS_LOG_SECURE=0
g_wait_for_user_name = 0
g_client_ip = ''

class LogParser(object):

    #初始化secure文件游标的初始位置，移到文件末尾
    def Init_Log_Secure_Pos(self):
        global g_POS_LOG_SECURE
        try:
            # debian ubuntu
            if os_version["type"] == "debian":
                f = open( '/var/log/auth.log', 'r' )
            # redhat centos and others
            else:
                f = open( '/var/log/secure', 'r' )
            f.seek( 0, 2 )
            g_POS_LOG_SECURE = f.tell( )
        except Exception as e:
            PrntLog.error('Failed Init_Log_Secure_Pos: %s'%e)
        finally:
            if 'f' in locals( ):
                f.close( )

    #操作和回显日志文件解析
    def Parser_Log(self,action, logPath, logName):
        try:
            #非log日志不处理
            if logName[0] == '.'or logName.split('.')[-1] != 'log':
                return

            linkInfo = get_linkInfo_from_logname( logPath, logName )
            if not linkInfo:
                PrntLog.info('Failed: get_linkInfo_from_logname %s'%logName)
                return False

            if (logPath.find( '/ssh' ) >= 0):
                parser_log_ssh(logPath, logName,linkInfo)
            elif (logPath.find( '/local' ) >= 0):
                parser_log_local( logPath, logName, linkInfo )
            elif (logPath.find( '/x11' ) >= 0):
                parser_log_x11( logPath, logName, linkInfo )
        except Exception as e:
            PrntLog.error('Failed Parser_Log: %s %s %s %s'%(action,logPath,logName,e))
            PrntLog.error("Parser_Log fail: %s" % traceback.format_exc())

    # 解析登录日志secure
    def Parser_Log_Secure(self):
        global g_POS_LOG_SECURE
        try:
            # debian ubuntu
            if os_version["type"] == "debian":
                f = open( '/var/log/auth.log', 'r' )
            # redhat centos and others
            else:
                f = open( '/var/log/secure', 'r' )

            f.seek( 0, 2 )
            endPos = f.tell( )
            # secure日志轮转
            if (g_POS_LOG_SECURE > endPos):
                g_POS_LOG_SECURE = 0

            f.seek( g_POS_LOG_SECURE )
            for i in range( 1000 ):
                line = f.readline( ).rstrip( '\n' )
                if line == '':
                    break
                PrntLog.info( line )
                if 'session closed for user' in line and 'sshd' not in line:
                    # 图形界面退出 包括本地和x11
                    process_session_loginout( line )
                elif 'session closed for user' in line and 'sshd['  in line:
                    # SSH退出登录流程
                    process_ssh_logout( line )
                elif 'session opened for user' in line and 'sshd' not in line:
                    #图形界面登录 包括本地和x11
                    process_session_login(line)
                    '''
                elif 'Received disconnect from' in line and 'sshd' in line:
                    # SSH退出登录流程
                    PrntLog.info(line)
                    process_ssh_logout( line )
                    '''
                elif 'Failed password for ' in line and  'sshd[' in line:
                    #SSH登录失败
                    process_ssh_loginfail(line)
                elif ('pam: gdm-password:' in line and '(gdm-password:auth)' in line) \
                    or ('gdm[' in line and '(gdm:auth)' in line)\
					or ('(gdm-password:auth)' in line and 'gdm-password]' in line) \
                	or ('gdm-session-worker[' in line and ('(gdm:auth)' in line or '(gdm3:auth)' in line)):
                    #x11 本地图形 登录失败
                    process_session_loginfail(line)
                elif ('login: FAILED LOGIN' in line) or ('FAILED LOGIN' in line and 'login[' in line) :
                    #tty 登录失败
                    process_tty_loginfail( line )

            g_POS_LOG_SECURE = f.tell( )
        except Exception as e:
            PrntLog.error( 'Failed Parser_Log_Secure: %s' % e )
            PrntLog.error( "Parser_Log_Secure fail: %s" % traceback.format_exc( ) )

        finally:
            if 'f' in locals( ):
                f.close( )

    def HearBeat(self):
        try:
            global gLinkList
            # 做个链路保活检查
            check_linkInfo_isAlive()
            for i in range( len( gLinkList ) - 1, -1, -1 ):
                item = gLinkList[i]
                if item['LOGIN_TYPE'] == 'ssh':
                    #发送心跳报文
                    strMsg=MsgWrap(item).Msg_SSH_HeartBeat()
                    pf_oper.sendmsg(strMsg)
                    # 测试阻断操作
                    #strMsg = MsgWrap( item ).Msg_SSH_TestStopLink( )
                    #pf_oper.sendmsg( strMsg )
                    PrntLog.info('ssh heart beat: %s' %item)
                elif item['LOGIN_TYPE'] == 'x11':
                    strMsg = MsgWrap( item ).Msg_X11_HeartBeat( )
                    pf_oper.sendmsg( strMsg )
                    #测试阻断操作
                    #strMsg = MsgWrap( item ).Msg_X11_TestStopLink( )
                    #pf_oper.sendmsg( strMsg )
                    PrntLog.info('x11 heart beat: %s' %item)
                elif item['LOGIN_TYPE'] == 'local':
                    # 发送心跳报文
                    strMsg = MsgWrap( item ).Msg_LOCAL_HeartBeat( )
                    pf_oper.sendmsg( strMsg )
                    PrntLog.info('local heart beat: %s'%item)
        except Exception as e:
            PrntLog.error('Failed HearBeat: %s '%e)

        '''
        import time
        #测试增加用户
        strMsg = OperMsgParser().test_AddNewCount_Data('test4')
        pf_oper.sendmsg( strMsg )
        time.sleep( 2 )
        strMsg = OperMsgParser( ).test_AddNewCount_Data( 'test5')
        pf_oper.sendmsg( strMsg )

        time.sleep(2)
        # 测试修改密码
        strMsg = OperMsgParser( ).test_ChangePasswd_Data()
        pf_oper.sendmsg( strMsg )

        #修改用户名
        #time.sleep( 2 )
        #strMsg = OperMsgParser( ).test_ChangeAccountName_Data( )
        #pf_oper.sendmsg( strMsg )

        #删除用户
        #time.sleep( 2 )
        #strMsg = OperMsgParser( ).test_DelAccount_Data()
        #pf_oper.sendmsg( strMsg )

        #获取平创建的用户列表
        #time.sleep( 2 )
        #strMsg = OperMsgParser( ).test_getCreatAccountList_Data()
        #pf_oper.sendmsg( strMsg )

        # 基线核查
        #time.sleep( 2 )
        strMsg = OperMsgParser( ).test_BaseLineCheck( )
        pf_oper.sendmsg( strMsg )

        #禁用网卡
        strMsg = OperMsgParser( ).test_stopnetcard( '192.168.0.92')
        pf_oper.sendmsg( strMsg )
        '''

    def stopLinkAndSendRes(self,operlinkInfo):
        try:
            global gLinkList
            PrntLog.info ('stopLinkAndSendRes: %s '% operlinkInfo)
            for i in range( len( gLinkList ) - 1, -1, -1 ):
                linkInfo = gLinkList[i]
                if operlinkInfo['IP'] == linkInfo['LOCAL_IP'] and operlinkInfo['PID_NUM'] == linkInfo['PID_NUM']:
                    # 杀死指定进程
                    str = 'kill -16 ' + operlinkInfo['PID_NUM']
                    PrntLog.info(str)
                    ret = os.system( str )
                    linkInfo['ID'] = operlinkInfo['ID']
                    # 发送响应报文
                    strMsg = MsgWrap( linkInfo ).Msg_StopLink_Res_DATA()
                    pf_oper.sendmsg( strMsg )
                    gLinkList.remove( linkInfo )
                    PrntLog.info('Remove Link %s'%linkInfo)
        except Exception as e:
            PrntLog.error('Failed stopLinkAndSendRes: %s ' %e)

def parser_log_ssh(logPath, logName,linkInfo):
    global gLinkList
    # 进行链路信息匹配
    matchFlag = 0
    subDict={}
    for item in gLinkList:
        if (item['LOGIN_TYPE'] == 'ssh'and
                item['CLIENT_IP'] == linkInfo['CLIENT_IP'] and
                item['CLIENT_PORT'] == linkInfo['CLIENT_PORT'] ):
            matchFlag = 1
            if not item.has_key( linkInfo['time'] ) and logName.find( 'info.log' )<0:
                subDict['CMD_OFFSET'] = 0
                subDict['ECHO_OFFSET'] = 0
                subDict['TTY'] = linkInfo['TTY']
                subDict['ECHO_SIZE'] =0
                item[linkInfo['time']] = subDict

            # print('************ssh find ')
            break

    # 没有匹配到新增链路
    if (matchFlag == 0):
        # print('************ssh not find ')
        subDict['CMD_OFFSET'] = 0
        subDict['ECHO_OFFSET'] = 0
        subDict['TTY'] = linkInfo['TTY']
        subDict['ECHO_SIZE'] = 0
        linkInfo[linkInfo['time']] = subDict

        gLinkList.append( linkInfo )
        PrntLog.info('Add ssh link: %s'%linkInfo)
        item = linkInfo
        # 发送链路信息
        strMsg = MsgWrap( item ).Msg_SSH_Server_Data( )
        pf_oper.sendmsg( strMsg )

    if (logName.find( 'cmd.log' ) >= 0):
        offset = read_cmd_from_cmdfile_sendMsg( logPath, logName, item,item[linkInfo['time']] )
        item[linkInfo['time']]['CMD_OFFSET'] = offset
    elif (logName.find( 'echo.log' ) >= 0):
        offset = read_echo_from_echofile_sendMsg( logPath, logName, item,item[linkInfo['time']] )
        item[linkInfo['time']]['ECHO_OFFSET'] = offset
    elif (logName.find( 'info.log' ) >= 0):
        read_info_from_infofile_sendMsg( logPath, logName, item )


def parser_log_local(logPath, logName,linkInfo):
    global gLinkList
    # 进行链路信息匹配
    matchFlag = 0
    subDict={}
    for item in gLinkList:
        if item['LOGIN_TYPE'] != 'local':
            continue
        #本地图形界面操作
        if item['LOCAL_TYPE'] == 'gdm' and item['LOCAL_TYPE'] == linkInfo['LOCAL_TYPE']:
            if item['USER_NAME'] == linkInfo['USER_NAME']:
                matchFlag = 1
                if not item.has_key( linkInfo['time'] ) and logName.find( 'info.log' ) < 0:
                    subDict['CMD_OFFSET'] = 0
                    subDict['ECHO_OFFSET'] = 0
                    subDict['TTY'] = linkInfo['TTY']
                    subDict['ECHO_SIZE'] = 0
                    item[linkInfo['time']] = subDict
                #print('************local gdm find ')
                break
        #本地字符界面操作
        elif item['LOCAL_TYPE'] == 'text' and item['LOCAL_TYPE'] == linkInfo['LOCAL_TYPE']:
            #操作回显日志文件，严格匹配链路开始时间
            if logName.find( 'info.log' ) < 0:
                if item['time'] == linkInfo['time'] and item['USER_NAME'] == linkInfo['USER_NAME']:
                    matchFlag = 1
                    if not item.has_key( linkInfo['time'] ):
                        subDict['CMD_OFFSET'] = 0
                        subDict['ECHO_OFFSET'] = 0
                        subDict['TTY'] = linkInfo['TTY']
                        subDict['ECHO_SIZE'] = 0
                        item[linkInfo['time']] = subDict
                    #print('************local tty find ')
                    break
            else:
                #ssh info 文件，匹配用户名即可
                if item['USER_NAME'] == linkInfo['USER_NAME']:
                    matchFlag = 1
                    break
    # 没有匹配到,新增链路
    if (matchFlag == 0):
        #print('************local not find ')
        if logName.find( 'info.log' ) < 0:
            subDict['CMD_OFFSET'] = 0
            subDict['ECHO_OFFSET'] = 0
            subDict['TTY'] = linkInfo['TTY']
            subDict['ECHO_SIZE'] = 0
            linkInfo[linkInfo['time']] = subDict

        gLinkList.append( linkInfo )
        PrntLog.info('Add local Link: %s'%linkInfo)
        item = linkInfo

        # 发送链路信息
        #print('**********need to send link info.....')
        strMsg = MsgWrap( item ).Msg_LOCAL_Login_Data( )
        pf_oper.sendmsg( strMsg )

    if (logName.find( 'cmd.log' ) >= 0):
        offset = read_cmd_from_cmdfile_sendMsg( logPath, logName, item, item[linkInfo['time']] )
        item[linkInfo['time']]['CMD_OFFSET'] = offset
    elif (logName.find( 'echo.log' ) >= 0):
        offset = read_echo_from_echofile_sendMsg( logPath, logName, item ,item[linkInfo['time']] )
        item[linkInfo['time']]['ECHO_OFFSET'] = offset
    elif (logName.find( 'info.log' ) >= 0):
        read_info_from_infofile_sendMsg( logPath, logName, item )


def parser_log_x11(logPath, logName,linkInfo):
    global gLinkList
    # 进行链路信息匹配
    matchFlag = 0
    subDict={}
    for item in gLinkList:
        if (item['LOGIN_TYPE'] == 'x11'and
                item['CLIENT_IP'] == linkInfo['CLIENT_IP'] and
                item['CLIENT_PORT'] == linkInfo['CLIENT_PORT']):
                    matchFlag = 1
                    if not item.has_key(linkInfo['time']) and logName.find( 'info.log' )<0:
                        subDict['CMD_OFFSET']  = 0
                        subDict['ECHO_OFFSET'] = 0
                        subDict['TTY'] = linkInfo['TTY']
                        subDict['ECHO_SIZE'] =0
                        item[linkInfo['time']]=subDict
                    #print('************x11 find ')
                    break


    # 没有匹配到,新增链路
    if (matchFlag == 0):
        #print('************x11 not find ')
        if logName.find( 'info.log' )<0:
            subDict['CMD_OFFSET'] = 0
            subDict['ECHO_OFFSET'] = 0
            subDict['TTY'] = linkInfo['TTY']
            subDict['ECHO_SIZE'] = 0
            linkInfo[linkInfo['time']] = subDict

        gLinkList.append( linkInfo )
        PrntLog.info('Add x11 Link: %s'%linkInfo)
        item = linkInfo

        # 发送X11登录信息
        #print('**********need to send x11 link info.....')
        strMsg = MsgWrap( item ).Msg_X11_Login_Data( )
        pf_oper.sendmsg( strMsg )


    if (logName.find( 'cmd.log' ) >= 0):
        offset = read_cmd_from_cmdfile_sendMsg( logPath, logName, item,item[linkInfo['time']] )
        item[linkInfo['time']]['CMD_OFFSET'] = offset
    elif (logName.find( 'echo.log' ) >= 0):
        offset = read_echo_from_echofile_sendMsg( logPath, logName, item, item[linkInfo['time']])
        item[linkInfo['time']]['ECHO_OFFSET'] = offset
    elif (logName.find( 'info.log' ) >= 0):
        read_info_from_infofile_sendMsg( logPath, logName, item )

#解析日志文件名获取链路信息
def get_linkInfo_from_logname(logPath, logName):
    if (logPath.find( '/ssh' ) >= 0):
        return get_ssh_linkInfo_from_logname( logName )
    elif (logPath.find( '/local' ) >= 0):
        return get_local_linkInfo_from_logname( logName )
    elif (logPath.find( '/x11' ) >= 0):
        return get_x11_linkInfo_from_logname( logName )

##SSH登录文件名解析
def get_ssh_linkInfo_from_logname(logName):
    strSplit=logName.split('-')
    if len(strSplit) != 7:
        PrntLog.error("Failed:get_ssh_linkInfo_from_logname %s " %logName)
        return False
    linkInfo = {}
    linkInfo['LOGIN_TYPE']   = 'ssh'
    linkInfo['CLIENT_IP']    = strSplit[0]
    linkInfo['CLIENT_PORT']  = strSplit[1]
    linkInfo['USER_NAME']    = strSplit[2]
    linkInfo['time']          = strSplit[3]
    linkInfo['TTY']           = strSplit[4]
    linkInfo['LOCAL_IP']     = strSplit[5]
    pos=0
    for str in linkInfo['TTY']:
        if str.isdigit( ):
            break
        pos=pos+1

    tty=linkInfo['TTY'][:pos]+'/'+linkInfo['TTY'][pos:]
    cmdline="ps -ef |grep -v grep |grep sshd |grep " + linkInfo['USER_NAME'] +" |grep "+tty +" | awk '{print $2}'"

    fp=os.popen(cmdline)
    linkInfo['PID_NUM'] = fp.readline( ).rstrip('\n')
    fp.close()
    if  linkInfo['PID_NUM']== '':
        return False

    return linkInfo

#本地登录文件名解析
def get_local_linkInfo_from_logname(logName ):
    strSplit = logName.split( '-' )
    if len( strSplit ) != 5:
        PrntLog.error("Failed:get_local_linkInfo_from_logname %s" % logName)
        return False
    linkInfo = {}
    linkInfo['LOGIN_TYPE'] = 'local'
    linkInfo['USER_NAME'] = strSplit[0]
    linkInfo['time']       = strSplit[1]
    linkInfo['TTY']        = strSplit[2]
    linkInfo['LOCAL_TYPE'] = strSplit[3]
    linkInfo['LOCAL_IP']  = get_host_ip()
    if not linkInfo['LOCAL_IP']:
        PrntLog.error('Failed: get_host_ip. %s ' % logName)
        return False

    #print(linkInfo)
    return linkInfo

#x11文件名解析
def get_x11_linkInfo_from_logname(logName):
    strSplit = logName.split( '-' )
    if len( strSplit ) != 5:
        PrntLog.info("Failed:get_x11_linkInfo_from_logname %s" % logName)
        return False
    linkInfo = {}
    linkInfo['LOGIN_TYPE'] = 'x11'
    linkInfo['USER_NAME'] = strSplit[0]
    linkInfo['time'] = strSplit[1]
    linkInfo['TTY'] = strSplit[2]
    linkInfo['SESSION_PID'] = strSplit[3]

    (localip, source_ip, source_port)=get_x11_linkInfo_by_Pid(linkInfo['SESSION_PID'])
    if localip== '':
        PrntLog.info('Failed: get x11 Link failed! %s '% logName )
        return  False
    linkInfo['LOCAL_IP'] = localip
    linkInfo['CLIENT_IP'] = source_ip
    linkInfo['CLIENT_PORT'] = source_port
    linkInfo['PID_NUM'] = linkInfo['SESSION_PID']
    return linkInfo

def getEchofileSize(logPath,cmdfileName):
    echofilename=cmdfileName.replace('-cmd.log','-echo.log')
    echofilepath=os.path.join( logPath, echofilename )    
    if os.path.exists( echofilepath ):
        fsize = os.path.getsize( echofilepath )
        #print(echofilepath,fsize)
        return fsize
    else:
        return 0


import traceback
#读取操作日志文件，并发送报文
def read_cmd_from_cmdfile_sendMsg(logPath, logName,linkInfo,itemDict):
    try:
        itemDict['ECHO_SIZE']=getEchofileSize(logPath,logName)
        fullFileName = os.path.join( logPath, logName )
        f = open( fullFileName, 'r' )
        f.seek(itemDict['CMD_OFFSET'])
        offset_flag=itemDict['CMD_OFFSET']
        for i in range( 1000 ):
            line = f.readline( ).rstrip('\n')
            if line == '':
                break
            #跳过第一行
            if(offset_flag==0):
                offset_flag = f.tell( )
                continue
            PrntLog.info(line)
            #获取信息，发送操作报文
            strMsg = MsgWrap( linkInfo, itemDict ).Msg_Cmd_DATA( line )
            if strMsg!='':
                pf_oper.sendmsg( strMsg )
        offset=f.tell()
        f.close()
        return offset
    except Exception as e:
        PrntLog.error('Failed read_cmd_from_cmdfile_sendMsg: %s '%e)
        PrntLog.error( "read_cmd_from_cmdfile_sendMsg fail: %s" % traceback.format_exc( ) )
        if 'f' in locals( ):
            f.close( )


#读取回显日志文件，并发送报文
def read_echo_from_echofile_sendMsg(logPath, logName,linkInfo,itemDict):
    try:
        fullFileName = os.path.join( logPath, logName )
        f = open( fullFileName, 'r' )
        fsize = os.path.getsize( fullFileName )
        #print('ECHO_SIZE %s  fsize %s  %s'%(itemDict['ECHO_SIZE'],fsize,fullFileName))
        if itemDict['ECHO_SIZE'] + 6*1024 < fsize :
            f.seek( 0, 2 )
            offset = f.tell( )
            f.close( )
            return offset
     
        f.seek(itemDict['ECHO_OFFSET'],0)
        
        for i in range( 100 ):
            strLine=''
            for i in range(10):
                line = f.readline( )
                #print('aa',line)
                if line == '':
                    break
                else:
                    strLine = strLine + line

            if strLine == '':
                break
            #PrntLog.info( strLine )
            #获取信息，发送操作报文
            strMsg = MsgWrap( linkInfo, itemDict).Msg_Echo_DATA(strLine)
            pf_oper.sendmsg( strMsg )
        offset=f.tell()
        f.close()
        return offset
    except Exception as e:
        PrntLog.error('Failed read_echo_from_echofile_sendMsg: %s '%e)
        PrntLog.error( "read_echo_from_echofile_sendMsg fail: %s" % traceback.format_exc( ) )
        if 'f' in locals( ):
            f.close( )


# A->B->C 链路处理
def read_info_from_infofile_sendMsg(logPath, logName,linkInfo):
    try:
        fullFileName = os.path.join( logPath, logName )
        f = open( fullFileName, 'r' )
        forwardInfo = {}
        hasFinish=0
        for i in range( 20 ):
            line = f.readline( ).rstrip('\n')
            if line == '':
                break
            strList=line.split('=')
            if 'REMOTE_IP' == strList[0]:
                forwardInfo['REMOTE_IP'] = strList[1]
            elif 'REMOTE_HOST' == strList[0]:
                forwardInfo['REMOTE_HOST'] = strList[1]
            elif 'REMOTE_DT' == strList[0]:
                forwardInfo['REMOTE_DT'] =  strList[1]
            elif 'TTY_NUM' == strList[0]:
                forwardInfo['CURRENT_TTY'] =  strList[1]
                #最后一个参数
                hasFinish=1
                break
    except Exception as e:
        PrntLog.error('Failed read_info_from_infofile_sendMsg: %s'%e)
        if 'f' in locals( ):
            f.close()
        return

    f.close( )
    #参数没有写完，直接返回
    if hasFinish == 0:
        return

    #获取SSH进程和端口号

    #获取ssh的进程号
    cmdline='ps -A -opid,tty,cmd| grep -v grep |grep ssh-op |grep '+forwardInfo['CURRENT_TTY'] + ' |grep '+forwardInfo['REMOTE_HOST']
    PrntLog.info(cmdline)
    fp=os.popen( cmdline )
    ret=fp.readline( ).rstrip( '\n' )
    fp.close()
    if ret == '':
        PrntLog.error('SSH login fail. REMOTE_IP=%s  REMOTE_HOST=%s ' % (forwardInfo['REMOTE_IP'],forwardInfo['REMOTE_HOST']))
        return

    forward_pid=''
    for str in ret.split(' '):
        if str != '':
            forward_pid=str
            break

    #链路已经存在，返回
    if(linkInfo.has_key('FORWARD_PID') and forward_pid == linkInfo['FORWARD_PID']):
        return

    #获取SSH连接的本地端口号
    cmdline='/usr/local/sagent-3000-ns/netstat -tpn | grep ESTABLISHED |grep '+forward_pid
    PrntLog.info(cmdline)
    localip=''
    forward_port=''
    fp = os.popen( cmdline )
    for line in fp:
        if 'ESTABLISHED' not in line:
            continue
        strList= line.split(' ')
        for str in strList:
            if str.find(':')>=0:
                localip=str.split(':')[0]
                forward_port=str.split(':')[1]
                break
    fp.close()
    if localip != '':
        linkInfo['LOCAL_IP'] = localip
        linkInfo['FORWARD_PID'] = forward_pid
        linkInfo['FORWARD_PORT'] = forward_port
        linkInfo['REMOTE_IP'] = forwardInfo['REMOTE_IP']
        linkInfo['REMOTE_DT'] = forwardInfo['REMOTE_DT']
        linkInfo['CURRENT_TTY'] = forwardInfo['CURRENT_TTY']
        PrntLog.info('SSH remote sucessful! REMOTE_IP=%s' %linkInfo['REMOTE_IP'])
        #发送链路报文
        strMsg = MsgWrap( linkInfo ).Msg_SSH_Client_Data( )
        pf_oper.sendmsg( strMsg )
    else:
        PrntLog.info('SSH Link is not create!  REMOTE_IP=%s' % forwardInfo['REMOTE_IP'])
        if linkInfo.has_key('FORWARD_PID'):
            linkInfo['FORWARD_PID'] = ''
            linkInfo['FORWARD_PORT'] = ''
            linkInfo['REMOTE_IP'] = ''
            linkInfo['REMOTE_DT'] = ''
            linkInfo['CURRENT_TTY'] = ''

        os.system( 'echo SSH_RETRY=5 >> %s ' % fullFileName )

#处理SSH登录退出
def process_ssh_logout(strInfo):
    global gLinkList
    #Jun 15 00:54:20 localhost sshd[11136]: Received disconnect from 172.16.140.151: 11: disconnected by user
    #Jun 27 07:46:11 localhost sshd[15252]: pam_unix(sshd:session): session closed for user root
    pos=strInfo.find('sshd[')
    if pos<0:
        return False
    '''
    for i in range(pos,pos+15):
        if strInfo[i]==']':
            break
    pid=strInfo[pos+5:i]
'''
    for i in range(len(gLinkList)-1,-1,-1):
        linkInfo = gLinkList[i]
        if 'ssh' == linkInfo['LOGIN_TYPE'] and not judge_ssh_link_exist(linkInfo['PID_NUM']):
            #发送退出登录报文
            PrntLog.info('ssh logout:user=%s  pid=%s ' %(linkInfo['USER_NAME'], linkInfo['PID_NUM']))
            strMsg = MsgWrap( linkInfo ).Msg_SSH_Logout_Data( )
            pf_oper.sendmsg( strMsg )
            gLinkList.remove(linkInfo)
            PrntLog.info('Remove SSH logout link %s'%linkInfo)
            #此处没有停止循环，是为了容错

def process_ssh_loginfail(strInfo):
    #Jun 16 09:10:43 localhost sshd[19679]: Failed password for test from 172.16.140.151 port 53307 ssh2
    #Jun 27 05:46:38 localhost sshd[8715]: Failed password for invalid user 234 from 172.16.140.151 port 57583 ssh2
    strList=strInfo.split(' ')

    if strInfo.find('from')<0:
        PrntLog.error('Failed process_ssh_loginfail: %s'%strInfo)
        return
    (usrname,clientIp,clientPort)= ['', '', '']
    for i in range(len(strList)):
        if strList[i] == 'from':
            usrname=strList[i-1]
            clientIp=strList[i+1]
            clientPort=strList[i+3]
            break

    linkInfo={}
    linkInfo['USER_NAME'] = usrname
    linkInfo['CLIENT_IP'] = clientIp
    linkInfo['CLIENT_PORT'] = clientPort
    linkInfo['LOCAL_IP'] = get_host_ip()
    linkInfo['time'] = get_cuurent_time()

    (status, output) = commands.getstatusoutput('/usr/local/sagent-3000-ns/netstat -tpn|grep ' + clientIp + ':' + clientPort + '| awk \'{print $4}\'')
    localPort = output.split(':')[-1]
    proc_failed_login(clientIp, usrname, time.time(), localPort)
    #发送登录失败报文
    strMsg = MsgWrap( linkInfo ).Msg_SSH_LogFail_Data( )
    pf_oper.sendmsg( strMsg )
    PrntLog.info('SSH login failed!  usrname=%s clientIp=%s clientPort=%s '%(usrname,clientIp,clientPort))

def report_session_loginfail(usrname, rhost):
    linkInfo = {}
    linkInfo['USER_NAME'] = usrname
    linkInfo['time'] = get_cuurent_time( )
    linkInfo['LOCAL_IP'] = get_host_ip( )
    PrntLog.info('session login fail. usrname=%s  rhost=%s'%(usrname,rhost))

    if rhost =='':
        # 发送本地session登录失败报文
        strMsg = MsgWrap( linkInfo ).Msg_LOCAL_LogFail_Data( )
    else:
        if os_version["type"] == "redhat":
            if os_version["version"] == 5:
                keystr = 'gdm-binary'
            elif os_version["name"] =='centos' and os_version["version"] == 7:
                keystr = 'lightdm-gtk'
            elif os_version["name"] =='redhat' and os_version["version"] == 7:
                keystr = 'lightdm'
            else:
                keystr = '-session'
        else:
            keystr = '-session'

        linkInfo['CLIENT_IP'] = rhost
        cmdline="/usr/local/sagent-3000-ns/netstat -ntp | grep %s | grep %s: | head -n 1|awk '{print $5}'" % (keystr,rhost)
        (status, output) = commands.getstatusoutput(cmdline)
        linkInfo['CLIENT_PORT'] = output.split(':')[-1]
        cmdline="/usr/local/sagent-3000-ns/netstat -ntp | grep %s | grep %s: | head -n 1|awk '{print $4}'"  %(keystr,rhost)
        (status, output) = commands.getstatusoutput(cmdline)
        localPort = output.split(':')[-1]
        # 发送x11登录失败报文
        strMsg = MsgWrap( linkInfo ).Msg_X11_LogFail_Data( )
        proc_failed_login(rhost, usrname, time.time(), localPort)

    pf_oper.sendmsg( strMsg )

def process_session_loginfail(strInfo):
   #Jul 10 02:48:29 localhost pam: gdm-password: pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=172.16.140.151:1 ruser= rhost=172.16.140.151  user=nari   ---x11
   #Jul 10 03:46:56 localhost pam: gdm-password: pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=nari   --local session
   #Aug  4 15:43:01 localhost gdm[3081]: pam_unix(gdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=root        ----rhel5.6
   #Aug  4 15:44:18 localhost gdm[3081]: pam_succeed_if(gdm:auth): error retrieving information about user qqqqqq                                 ----rhel5.6
   #Jan 31 03:29:11 nari-desktop gdm-session-worker[31147]: pam_unix(gdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=nari  ----ubunt10
   #Feb  1 21:56:01 debian gdm-session-worker[8583]: pam_unix(gdm3:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=root      ----debian6.0
    global g_wait_for_user_name
    global g_client_ip

    if g_wait_for_user_name == 0 and 'authentication failure;' not in strInfo:
        return

    if g_wait_for_user_name == 1:
        if 'error retrieving information about user' in strInfo:
            usrname = strInfo.split(' ')[-1]
            report_session_loginfail(usrname, g_client_ip)
            g_wait_for_user_name = 0
        return

    strList = strInfo.split( ' ')
    usrname=''
    rhost=''
    for i in range(len(strList)):
        if strList[i].find('tty=') >= 0:
            tty=strList[i].split('=')[1]
            if tty == '':
                rhost=''
            elif tty.find(':') > 0:
                rhost=tty.split(':')[0]
            else:
                rhost=''

        if rhost == '' and strList[i].find('rhost=') >=0:
            rhost=strList[i].split('=')[1]
        elif strList[i].find('user=') >=0 and strList[i].find( 'ruser=' ) < 0:
            usrname=strList[i].split('=')[1]

    # 保存ip,后面查找用户名
    if usrname=='':
        g_wait_for_user_name = 1
        g_client_ip = rhost
        return
    PrntLog.info('process_session_loginfail: usrname=%s rhost=%s'%(usrname,rhost))
    report_session_loginfail(usrname, rhost)

def process_tty_loginfail(strInfo):
    #Jun 23 06:35:13 localhost login: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=tty2 ruser= rhost=  user=root  -kylin
    #Jul 10 03:48:20 localhost login: FAILED LOGIN 2 FROM (null) FOR root, Authentication failure
    #Jul 10 04:12:43 localhost login: FAILED LOGIN 2 FROM (null) FOR reeewt, User not known to the underlying authentication module
    #Jan 31 03:31:43 nari-desktop login[32569]: FAILED LOGIN (1) on '/dev/tty2' FOR 'nari', Authentication failure  -----ubuntu10
    #Feb  1 21:57:37 debian login[1589]: FAILED LOGIN (1) on '/dev/tty3' FOR 'root', Authentication failure  -----debian6.0
    strList = strInfo.split( ' ' )
    usrname=''
    if os_version["type"] == "debian" :
        for i in range( len( strList ) ):
            if strList[i] =='LOGIN' and strList[i+2] =='on' and strList[i+4] =='FOR' :
                usrname=strList[i+5].rstrip(',').strip('\'')
                break
    else:
        for i in range( len( strList ) ):
            if strList[i] =='LOGIN' and strList[i+2] =='FROM' and strList[i+4] =='FOR' :
                usrname=strList[i+5].rstrip(',')
                break

    if usrname=='':
        PrntLog.error('Failed process_tty_loginfail! strInfo= %s'%strInfo)
        return

    linkInfo = {}
    linkInfo['USER_NAME'] = usrname
    linkInfo['time'] = get_cuurent_time( )
    linkInfo['LOCAL_IP'] = get_host_ip( )

    PrntLog.info('tty login failed! usrname= %s '%usrname)
    # 发送tty登录失败报文
    strMsg = MsgWrap( linkInfo ).Msg_LOCAL_LogFail_Data( )
    pf_oper.sendmsg( strMsg )


def process_session_loginout(strInfo):
    #Jun 21 01:38:22 localhost gdm[23268]: pam_unix(gdm:session): session closed for user root   --- kylin
    #Jun 21 07:58:57 localhost login: pam_unix(login:session): session closed for user nari
    #Jul  4 22:52:15 localhost pam: gdm-password: pam_unix(gdm-password:session): session closed for user root  --rhel6.4
    #Aug  4 15:38:49 localhost gdm[3081]: pam_unix(gdm:session): session closed for user root ----rhel5.6
    #Jan 31 03:27:31 nari-desktop gdm-session-worker[25067]: pam_unix(gdm:session): session closed for user nari ----ubuntu10
    strList = strInfo.split(' ')
    if strList[-1] == 'lightdm' or strList[-1] == 'gdm':
        return
    '''
    if os_version["type"] == "redhat" and os_version["version"] == 5:
        keystr = 'gdm['
    elif os_version["name"] == "redhat" and os_version["version"] == 7:
        keystr = 'gdm-password]'
    elif os_version["name"] == "centos" and os_version["version"] == 7:
        if strInfo.find('login:') < 0:
            keystr = ':session'
        else:
            keystr = 'dm:session'
    elif os_version["type"] == "debian": #ubuntu10
        keystr = 'gdm-session-worker['
    else:
        keystr = 'pam:'
    pos = strInfo.find( keystr )
    if pos < 0:
        if strInfo.find( 'login:' )>=0:
            #本地tty终端退出处理
            return process_local_tty_loginout(strInfo)
        else:
            return False
    '''
    username = strInfo.split( ' ' )[-1]
    if strInfo.find( 'login:' ) >= 0:
        # 本地tty终端退出处理
        return process_local_tty_loginout( strInfo )

    # 查找x11链路
    time.sleep(3)
    if os_version["type"] == "redhat":
        if os_version["name"] == "redhat" and os_version["version"] == 7:
            keystr = '"kdeinit4: ksm"'
        else:
            keystr = '-sessio'
    else:
        keystr = '-sessio'

    x11List = get_x11_linkInfo_by_ProcessName( keystr )
    ret=find_linkInfo_for_logout(x11List)
    if not ret:
        #没有x11链路退出，则为本地图形界面退出处理
        process_local_session_logout( username )
    else:
        global gLinkList
        linkInfo=ret
        strMsg = MsgWrap( linkInfo ).Msg_X11_Loginout_Data( )
        pf_oper.sendmsg( strMsg )
        gLinkList.remove( linkInfo )
        PrntLog.info( 'Remove x11 logout %s' % linkInfo )


#x11退出处理, 成功返回;True   失败返回False
def process_x11_logout(username):
    global gLinkList
    for i in range( len( gLinkList ) - 1, -1, -1 ):
        linkInfo = gLinkList[i]
        if 'x11'==linkInfo['LOGIN_TYPE'] :
            #发送x11退出报文
            PrntLog.info ('x11 session log out:  username= %s '%username)
            strMsg = MsgWrap( linkInfo ).Msg_X11_Loginout_Data( )
            pf_oper.sendmsg( strMsg )
            gLinkList.remove(linkInfo)
            PrntLog.info('Remove x11 logout %s'%linkInfo)


#处理本地图形登录退出
def process_local_session_logout(username):
    global gLinkList
    for linkInfo in gLinkList:
        if 'local' == linkInfo['LOGIN_TYPE'] and  'gdm'== linkInfo['LOCAL_TYPE'] and username == linkInfo['USER_NAME']:
            # 发送本地图形登录退出报文
            PrntLog.info ('local session log out: username= %s '% username)
            strMsg = MsgWrap( linkInfo ).Msg_LOCAL_Loginout_Data( )
            pf_oper.sendmsg( strMsg )
            gLinkList.remove( linkInfo )
            PrntLog.info('Remove local session %s'%linkInfo)
            return True

    return False

def process_local_tty_loginout(strInfo):
    global gLinkList
    username = strInfo.split( ' ' )[-1]
    loginUserList=get_current_login_user()
    for i in range( len( gLinkList ) - 1, -1, -1 ):
        linkInfo = gLinkList[i]
        if  'local' == linkInfo['LOGIN_TYPE'] and 'text' == linkInfo['LOCAL_TYPE'] :
            hasMatch = 0
            for usrInfo in loginUserList:
                if linkInfo['USER_NAME'] == usrInfo['username'] and linkInfo['TTY'] == usrInfo['tty']:
                    hasMatch = 1
                    break
            if hasMatch==0:
                #发送tty退出报文
                PrntLog.info('local tty logout: username =%s tty=%s ' %( linkInfo['USER_NAME'], linkInfo['TTY']))
                strMsg = MsgWrap( linkInfo ).Msg_LOCAL_Loginout_Data( )
                pf_oper.sendmsg( strMsg )
                gLinkList.remove(linkInfo)
                PrntLog.info('Remove tty logout %s'%linkInfo)

def check_linkInfo_isAlive():
    delete_log_file()
    check_global_link()

def delete_log_file():
    path = '/tmp/.record'
    # 遍历日志文件，将退出的session的日志文件删除
    for dirpath, dirnames, filenames in os.walk( path ):
        for file in filenames:
            fullpath = os.path.join( dirpath, file )
            if '-cmd.log' in fullpath:
                sessionname = fullpath.rstrip( 'cmd.log' )
            elif '-echo.log' in fullpath:
                sessionname = fullpath.rstrip( 'echo.log' )
            else:
                continue

            if not judge_script_exist( sessionname ):
                cmdfilename = sessionname + 'cmd.log'
                echofilename = sessionname + 'echo.log'

                PrntLog.info( 'Delete file %s' % sessionname )
                if os.path.exists(cmdfilename):
                    os.remove(cmdfilename )
                if os.path.exists(echofilename):
                    os.remove(echofilename )

def check_global_link():
    global gLinkList
    loginUserList = get_current_login_user( )
    for i in range( len( gLinkList ) - 1, -1, -1 ):
        linkInfo = gLinkList[i]
        #本地tty登录
        if  'local' == linkInfo['LOGIN_TYPE'] and 'text' == linkInfo['LOCAL_TYPE']:
            if not linkInfo.has_key('TTY'):
                continue
            hasMatch = 0
            for usrInfo in loginUserList:
                if linkInfo['USER_NAME'] == usrInfo['username'] and linkInfo['TTY'] == usrInfo['tty']:
                    hasMatch = 1
                    break
            if hasMatch==0:
                #发送tty退出报文
                PrntLog.info('keep alive : local tty logout %s %s' %( linkInfo['USER_NAME'], linkInfo['TTY']))
                strMsg = MsgWrap( linkInfo ).Msg_LOCAL_Loginout_Data( )
                pf_oper.sendmsg( strMsg )
                gLinkList.remove(linkInfo)
                PrntLog.info('Remove tty check alive %s'%linkInfo)
        elif 'x11' == linkInfo['LOGIN_TYPE'] :
            (localip, source_ip, source_port) = get_x11_linkInfo_by_Pid( linkInfo['PID_NUM'] )
            if localip == '':
                strMsg = MsgWrap( linkInfo ).Msg_X11_Loginout_Data( )
                pf_oper.sendmsg( strMsg )
                gLinkList.remove( linkInfo )
                PrntLog.info( 'check_global_link: Remove x11 link %s' % linkInfo )
        elif 'ssh'== linkInfo['LOGIN_TYPE'] :
            if not judge_ssh_link_exist( linkInfo['PID_NUM']):
                strMsg = MsgWrap( linkInfo ).Msg_SSH_Logout_Data( )
                pf_oper.sendmsg( strMsg )
                gLinkList.remove( linkInfo )
                PrntLog.info( 'check_global_link: Remove SSH link link %s' % linkInfo )


        '''
        #本地图形登录
        elif 'local' == linkInfo['LOGIN_TYPE'] and 'gdm' == linkInfo['LOCAL_TYPE'] :
            hasMatch = 0
            for usrInfo in loginUserList:
                if linkInfo['USER_NAME'] == usrInfo['username'] and ':0.0' == usrInfo['tty']:
                    hasMatch = 1
                    break
            if hasMatch == 0:
                # 发送本地图形退出报文
                PrntLog.info('keep alive : local session logout %s %s' % (linkInfo['USER_NAME'],linkInfo['TTY']))
                strMsg = MsgWrap( linkInfo ).Msg_LOCAL_Loginout_Data( )
                pf_oper.sendmsg( strMsg )
                gLinkList.remove( linkInfo )
        '''

#session 登录，包括本地登录和x11
def process_session_login(strInfo):
    #Jul  5 02:01:35 localhost pam: gdm-password: pam_unix(gdm-password:session): session opened for user nari by (uid=0)   -------rhel6.4
    #Aug  4 15:35:38 localhost gdm[3081]: pam_unix(gdm:session): session opened for user root by (uid=0)                    -------rhel5.6
    #Jan 31 03:10:03 nari-desktop gdm-session-worker[25067]: pam_unix(gdm:session): session opened for user nari by (uid=0) -------ubuntu10
    loginuserlist = strInfo.split(' ')
    if loginuserlist[-3] == 'lightdm' or loginuserlist[-3] == 'gdm':
        return
    '''
    if os_version["type"] == "redhat" and os_version["version"] == 5:
        keystr = 'gdm['
    elif os_version["name"] == "redhat" and os_version["version"] == 7:
        keystr = 'gdm-password]'
    elif os_version["name"] == "centos" and os_version["version"] == 7:
        keystr = ':session)'
    elif os_version["type"] == "debian": #ubuntu10
        keystr = 'gdm-session-worker['
    else:
        keystr = 'pam:'
    pos = strInfo.find(keystr)
    if pos<0:
        return False
    '''
    strList = strInfo.split(' ')
    usrname=''
    for i in range(len(strList)):
        if strList[i]=='opened' and strList[i+1]=='for'and strList[i+2]=='user':
            usrname=strList[i+3]
            break

    #查找x11链路
    time.sleep(3)
    if os_version["type"] == "redhat":
        # lightdm + kde
        if os_version["name"] == "redhat" and os_version["version"] == 7:
            time.sleep(1)
            keystr = '"kdeinit4: ksm"'
        else:
            keystr = '-sessio'
    else:
        keystr = '-sessio'
    x11List=get_x11_linkInfo_by_ProcessName(keystr)
    ret=find_x11Link_for_login(x11List)
    if not ret:
        #不能找到新增x11链路，则为本地session登录
        process_session_console_login( usrname)
    else:
        #x11数据区还不存在，则为x11登录
        process_x11_login(usrname,ret)

def find_linkInfo_for_logout(x11List):
    global gLinkList
    for linkInfo in gLinkList:
        if 'x11' != linkInfo['LOGIN_TYPE']:
            continue
        hasMatch = 0
        for x11Link in x11List:
            if x11Link['PID_NUM'] == linkInfo['PID_NUM']:
                hasMatch = 1
                break
        if hasMatch == 0:
            # 数据区中x11 无法匹配到链路，表明x11退出
            return linkInfo

    #数据区中x11与链路可以匹配上
    return False

def find_x11Link_for_login(x11List):
    global  gLinkList
    for x11Link in x11List:
        hasMatch=0
        for linkInfo in gLinkList:
            if 'x11' ==  linkInfo['LOGIN_TYPE'] and x11Link['PID_NUM'] == linkInfo['PID_NUM']:
                hasMatch=1
                break
        if hasMatch==0:
            #x11链路未匹配到数据区
            return x11Link
    #新增登录，不是x11链路，全部可以匹配到数据区
    return False

#x11登录,添加链路信息
def process_x11_login(usrname,x11Link):
    global gLinkList
    linkInfo={}
    linkInfo['LOGIN_TYPE'] = 'x11'
    linkInfo['CLIENT_IP'] = x11Link['CLIENT_IP']
    linkInfo['CLIENT_PORT'] = x11Link['CLIENT_PORT']
    linkInfo['USER_NAME'] = usrname
    linkInfo['time'] = get_cuurent_time()
    linkInfo['LOCAL_IP'] = x11Link['LOCAL_IP']
    linkInfo['PID_NUM'] = x11Link['PID_NUM']

    gLinkList.append(linkInfo)
    PrntLog.info('Add x11 Login : %s'%linkInfo)
    #发送x11登录消息报文
    strMsg = MsgWrap( linkInfo ).Msg_X11_Login_Data( )
    pf_oper.sendmsg( strMsg )

#本地图形控制台登录
def process_session_console_login(usrname):
    global gLinkList
    linkInfo = {}
    linkInfo['LOGIN_TYPE'] = 'local'
    linkInfo['LOCAL_TYPE'] = 'gdm'
    linkInfo['USER_NAME'] = usrname
    linkInfo['time'] = get_cuurent_time()
    linkInfo['LOCAL_IP'] = get_host_ip( )
    if not linkInfo['LOCAL_IP']:
        PrntLog.error('Failed: get_host_ip. %s ' % usrname)
        return False

    gLinkList.append( linkInfo )
    PrntLog.info('Add local session :%s'%linkInfo)
    # 发送本地登录消息报文
    strMsg = MsgWrap( linkInfo ).Msg_LOCAL_Login_Data( )
    pf_oper.sendmsg( strMsg )
    PrntLog.info('local session login : usrname =%s localip=%s'%( usrname ,linkInfo['LOCAL_IP']))

def get_x11_linkInfo_by_Pid(pid):
    # 判断是否存在x11链路
    #cmdline = 'netstat -tpn | grep ESTABLISHED |grep ' + pid+'/gnome-session'
    cmdline = '/usr/local/sagent-3000-ns/netstat -tpn | grep ESTABLISHED |grep ' + pid + '/' #+ ' |grep -session '
    #PrntLog.info(cmdline)
    localip = ''
    source_ip=''
    source_port=''
    fp = os.popen( cmdline )
    for line in fp:
        if 'ESTABLISHED' not in line:
            continue
        strList = line.split( ' ' )
        for i in range( len( strList ) ):
            str = strList[i]
            if str.find( ':' ) >= 0:
                localip = str.split( ':' )[0]
                break

        for j in range( i + 1, len( strList ) ):
            str = strList[j]
            if str.find( ':' ) >= 0:
                source_ip = str.split( ':' )[0]
                source_port = str.split( ':' )[1]
                break
    fp.close()
    return (localip,source_ip,source_port)

#获取当前登录用户who的列表
def get_current_login_user():
    loginUserList=[]
    fp = os.popen('who')
    for line in fp:
        usrInfo={}
        strList=line.split(' ')
        usrInfo['username']=strList[0]
        for i in range(1,100):
            if(strList[i] != ''):
                usrInfo['tty']=strList[i].replace('/','')
                break
        loginUserList.append(usrInfo)
    fp.close()
    return loginUserList

def get_x11_linkInfo_by_ProcessName(processname):
    # 判断是否存在x11链路
    cmdline = "/usr/local/sagent-3000-ns/netstat -tpn | grep ESTABLISHED |grep %s " % processname
    PrntLog.info(cmdline)
    x11List=[]

    fp = os.popen( cmdline )
    # tcp        0      0 192.168.0.92:47668          172.16.140.151:6001         ESTABLISHED 2216/gnome-session
    for line in fp:
        if 'ESTABLISHED' not in line:
            continue
        x11Link = {}
        strList = line.split( ' ' )
        PrntLog.info('get_x11_linkInfo_by_ProcessName  strList=%s'%strList)
        for i in range( len( strList ) ):
            str = strList[i]
            if str.find( ':' ) >= 0:
                x11Link['LOCAL_IP'] = str.split( ':' )[0]
                break

        for j in range( i + 1, len( strList ) ):
            str = strList[j]
            if str.find( ':' ) >= 0 and str.find( '/' ) < 0:
                x11Link['CLIENT_IP'] = str.split( ':' )[0]
                x11Link['CLIENT_PORT'] = str.split( ':' )[1]
            #elif processname in str:
            elif str.find( '/' ) >= 0:
                #x11Link['PID_NUM'] = str.rstrip( '/'+processname )
                x11Link['PID_NUM'] = str.split('/')[0]
                x11List.append(x11Link)
                break
    fp.close()
    PrntLog.info('x11 linkInfo %s '%(x11List))
    return x11List

def judge_ssh_link_exist(pid):
    cmdline = "ps -ef |grep -v grep |grep sshd |grep " + pid
    PrntLog.info(cmdline)
    fp = os.popen( cmdline )
    for line in fp:
        if pid in line and 'sshd' in line:
            fp.close()
            return True
    fp.close()
    return False

def judge_script_exist(keystr):
    cmdline = 'ps -A -ocmd| grep -v grep |grep script |grep ' + keystr
    fp = os.popen( cmdline )
    for line in fp:
        if keystr in line:
            fp.close()
            return True
    fp.close()
    return False

def getParentPid(pid):
    (procppid) = commands.getoutput( 'ps -p ' + pid + ' -o ppid=' )
    ppid = procppid.strip( )
    return ppid

import threading
def judge_Is_ExistsProcess(judgePid):
    proList=['top','tcpdump','tail -f']
    for process in proList:
        cmdline="ps -A -opid,cmd|grep -v grep |grep -w '%s'"% process
        print(threading.current_thread().name,cmdline)
        output=commands.getoutput( cmdline)
        if output =='':
            continue
        else:
            pidList=[]
            outList=output.split('\n')
            for out in outList:
                pidList.append(out.split()[0])

        for pid in pidList:
            while True:
                ppid=getParentPid(pid)
                if ppid == judgePid:
                    return True
                elif ppid =='1' or ppid == '':
                    break
                print('pid = %s  ppid=%s'%(pid,ppid))
                pid=ppid
                #time.sleep(1)
    return False