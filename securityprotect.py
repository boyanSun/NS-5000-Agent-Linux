#!/usr/bin/env python
# -*- coding:utf-8 -*-

import getpass
import os
import hashlib
import sys
import commands
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

ShadowFile='agent.sha'
IntegrityFile='.agent.sha'

def genrateWord(word):
    str1=str(76*345)
    str2='_N-~l^8_$%^&*(GH^GJJKL^&YUHJE'[3:9]
    md5_obj = hashlib.md5( )
    md5_obj.update( word )
    str3 = md5_obj.hexdigest( )
    strLine="%s%s%s"%(str1,str2,str3)
    strLine=strLine[4:20]
    return strLine

def readshadowfile():
    try:
        with open( ShadowFile, 'r' ) as f:
            lineStr = f.readline( )
            cryPass=lineStr.split()[0]
            hashStr=lineStr.split()[1]
            return (cryPass,hashStr)
    except Exception as e:
        print('read shadow file error!')
        return ('0','0')

def writeshadowfile(strline):
    try:
        with open( ShadowFile, 'w' ) as f:
            f.write(strline )
        output = commands.getoutput( 'rm -rf %s ' % (IntegrityFile) )
        output = commands.getoutput( 'cp %s %s '%(ShadowFile,IntegrityFile) )
    except Exception as e:
        print('write shadow file error! %s', e)

def genratedefaultpass(objCrypto):
    passwd='Nari.1234'
    cryPass=objCrypto.encrypt(passwd)
    hashStr=hashlib.sha1( passwd ).hexdigest( )
    strline='%s %s'%(cryPass,hashStr)
    writeshadowfile(strline)
    return (passwd,hashStr)

def setPasswdtoShadow(objCrypto,passwd):
    cryPass = objCrypto.encrypt( passwd )
    hashStr = hashlib.sha1( passwd ).hexdigest( )
    strline = '%s %s' % (cryPass, hashStr)
    writeshadowfile( strline )
    return True

def IntegrityProtect():
    if os.path.exists(IntegrityFile):
        output = commands.getoutput( 'rm -rf %s ' % (ShadowFile) )
        output = commands.getoutput( 'cp %s %s ' % (IntegrityFile, ShadowFile) )
    else:
        print('shadow file integrity protect fail')

class prpcrypt( ):
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new( self.key, self.mode, self.key )
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 16
        count = len( text )

        if (count % length != 0):
            add = length - (count % length)
        else:
            add = 0
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt( text )
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex( self.ciphertext )

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new( self.key, self.mode, self.key )
        plain_text = cryptor.decrypt( a2b_hex( text ) )
        return plain_text.rstrip( '\0' )

def verifyPasswd(objCrypto,inputPass):
    if os.path.exists(ShadowFile):
        (cryPass, hashStr)=readshadowfile()
        try:
            passwd=objCrypto.decrypt( cryPass )
            if hashStr == hashlib.sha1( passwd ).hexdigest( ):
                pass
            else:
                print('shadow file has been modified! Integrity protection!')
                IntegrityProtect( )
                return False
        except:
            print('shadow file has been modified! Integrity protection!')
            IntegrityProtect()
            return False
        #print(passwd,hashStr)
    else:
        (passwd, hashStr)=genratedefaultpass(objCrypto)

    if inputPass==passwd:
        #print('passwd is ok')
        return True
    else:
        print('passwd is wrong')
        return False

def updateAgentConfigfile():
    if os.path.exists('agent.conf'):
        output = commands.getoutput( 'rm -rf .agent.conf ')
        output = commands.getoutput( 'cp agent.conf .agent.conf ')
        return True
    else:
        return False

def useage():
    print('Usage: securityproect <-m>|<-u>')
    print('   -m    modify passwd')
    print('   -u    update config file')

def main(argv):
    if len(argv) != 2 or ( argv[1] !='-m' and argv[1] !='-u'):
        useage()
        return

    inputPass = getpass.getpass( "Please input pasword:" )
    # print "passord", passord
    strWord = genrateWord( 'Nari.1234' )
    objCrypto = prpcrypt( strWord )  # 初始化密钥
    if not verifyPasswd( objCrypto, inputPass ):
        return

    if argv[1] =='-m':
        print('Changing password for securityprotect')
        pass1 = getpass.getpass( "New password:" )
        pass2 = getpass.getpass( "Retype new password:" )
        if pass1 !=pass2:
            print('Sorry, passwords do not match.')
            return

        if setPasswdtoShadow( objCrypto, pass1 ):
            print('passwd modify successfully.')
            return
    elif argv[1] =='-u':
        if updateAgentConfigfile():
            print('update config file successfully')

if __name__ == "__main__":
    main(sys.argv)








