#!/bin/bash

flag=0
if [ -f /usr/local/sagent-3000-ns/osinfo ] ;then
    OS=`cat /usr/local/sagent-3000-ns/osinfo | awk -F'-' '{print $1}'`
    VER=`cat /usr/local/sagent-3000-ns/osinfo | awk -F'-' '{print $2}'`
else
    if [ -f /etc/os-release ]; then
        # freedesktop.org and systemd
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        str=`head -n 1 /etc/redhat-release`
        if [[ $str == *"CentOS"* ]]
        then
            OS="CentOS"
        else
            OS="RedHat"
        fi
        VER=`echo $str |awk '{ print  $(NF-1) }'`
        flag=1
    elif type lsb_release >/dev/null 2>&1; then
        # linuxbase.org
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        # For some versions of Debian/Ubuntu without lsb_release command
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        # Older Debian/Ubuntu/etc.
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [ -f /etc/SuSe-release ]; then
        # Older SuSE/etc.
        ...
    else
        # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
        #OS=$(uname -s)
        #VER=$(uname -r)
        exit 2
    fi
fi

case $(uname -m) in
x86_64)
    ARCH=x86_64  # or AMD64 or Intel64 or whatever
    ;;
i*86)
    ARCH=x86  # or IA32 or Intel32 or whatever
    ;;
*)
    # leave ARCH as-is
    ;;
esac

if [ -f /etc/issue ] && [ $flag -eq 1 ]; then
    if [ $OS=="RedHat" ] || [ $OS=="CentOS" ]; then
        str=`head -n 1 /etc/issue`
        VER=`echo $str |awk '{ print  $(NF-1) }'`
    fi
fi

if [ $# -eq 1 ] ;then
    VER=${VER%%.*}
    echo "OS:"$OS
    echo "VER:"$VER
    echo "ARCH:"$ARCH
else
    echo -e "\nThe system information is:"
    echo "OS:"$OS
    echo "VER:"$VER
    echo "ARCH:"$ARCH
    echo -n "Please make sure OS type,enter Y/y to continue,enter N/n to stop: "
    read choose
    if [ "$choose"x == "n"x ] || [ "$choose"x == "N"x ]; then
        exit 1
    fi
fi

