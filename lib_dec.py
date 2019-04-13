#!/usr/bin/env python
# -*- coding:utf-8 -*-

import hashlib
import os
import base64 as b64
import sys
from utilsCommon import PrntLog

def xor_decrypt(secret, key):
    tips = b64.b64decode( secret.encode() ).decode()
    ltips = len(tips)
    lkey = len(key)
    secret = []
    num = 0
    for each in tips:
        if num >= lkey:
            num = num%lkey
        secret.append( chr( ord(each)^ord(key[num]) ) )
        num+=1
    return "".join( secret )

def get_md5(file_path):
    f = open(file_path,'rb')
    md5_obj = hashlib.md5()
    while True:
        d = f.read(8096)
        if not d:
            break
        md5_obj.update(d)
    hash_code = md5_obj.hexdigest()
    f.close()
    md5 = str(hash_code).lower()
    return md5

def dec_lib(libname, outfile):
    try:
        f = open(outfile)
        line = f.readline()
        f.close()

        out = xor_decrypt(line, 'WgQv^^!QSk*m')
        md5 = get_md5(libname)

        if out == md5:
            return 0
        else:
            return -1
    except Exception as e:
        PrntLog.error('dec_lib exception[%s]' % e)
        return -1

def useage():
    print('Usage: lib_dec libname outfile')
    print('libname: library to enc')
    print('outfile: enc result')

def main(argv):
    print(len(argv))
    if len(argv) != 3 :
        useage()
        os._exit(1)

    dec_lib(argv[1], argv[2])

if __name__ == "__main__":
    main(sys.argv)
