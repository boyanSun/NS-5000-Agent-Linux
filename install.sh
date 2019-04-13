#!/bin/bash

current_user=`whoami`
if [ $current_user != "root" ];then
    echo "Please do with root user!"
    exit 0
fi

install_dir=/usr/local/sagent-3000-ns
dir=`dirname "$0"`
cd $dir
cur_dir=`pwd`

if [ ! -d "$install_dir" ];then
    mkdir -p "$install_dir"
fi

cd "$install_dir"
tar xvf "$cur_dir"/dist.tar
