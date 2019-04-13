#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import hashlib
import os
import base64 as b64
import sys

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

def xor_encrypt(tips, key):
    ltips = len(tips)
    lkey = len(key)
    secret = []
    num=0
    for each in tips:
        if num >= lkey:
            num = num%lkey
        secret.append( chr( ord(each)^ord(key[num]) ) )
        num+=1
    return b64.b64encode( "".join( secret ).encode() ).decode()

def enc_lib(libname, outfile):
    try:
        md5 = get_md5(libname)
        out = xor_encrypt(md5, 'WgQv^^!QSk*m')
        os.system("echo \"%s\" > %s" % (out, outfile))
        print("enc_lib success, md5:%s, out:%s"%(md5, out))
        return 0
    except Exception as e:
        print('enc_lib failed, exception[%s]' % e)
        return -1

def useage():
    print('Usage: lib_enc libname outfile')
    print('libname: library to enc')
    print('outfile: enc result')

def main(argv):
    if len(argv) != 3 :
        useage()
        os._exit(1)

    enc_lib(argv[1], argv[2])

if __name__ == "__main__":
    main(sys.argv)








