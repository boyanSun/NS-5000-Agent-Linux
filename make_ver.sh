#!/bin/bash

wd=$(cd "$(dirname "$0")"; pwd)
cd $wd
echo $wd

source ./os_detect.sh
if [ $? -ne 0 ];then
    exit
fi
VER=${VER%%.*}

#version compiled in os 6 can be used for all.
OS_SUFFIX=$ARCH
if ([[ $OS == "RedHat"* ]] || [[ $OS == "CentOS"* ]]) && [[ $VER == "5" ]]
then
    OS_SUFFIX="5-"$ARCH
fi

targetname="SAGENT-3000-ns-linux-"$OS_SUFFIX
PYTHON=/usr/local/bin/python2.7
targetfiles="uninstall_config.sh session_user config_install.sh os_detect.sh agent.conf agent_public.key  baseline.sh logger.conf ssh-ns sftp-ns scp-ns  usb.ids version.txt license_install.sh build.log agent-daemon.sh gettime uninstall.sh ShlvlNumber"

rm -rf build dist *.spec $targetname

time=`date "+%Y%m%d"`

#Generating compile environment system information
echo 'Build date:' $time > build.log
echo "uname -a" >> build.log
uname -a  >> build.log

echo  "" >> build.log
echo 'getconf LONG_BIT' >> build.log
getconf LONG_BIT 1>>build.log 2>&1
$PYTHON -c "import sys;print('Big Endian' if sys.byteorder=='big'else 'Little Endian')" >> build.log

echo  "" >> build.log
$PYTHON -V 1>>build.log 2>&1
gcc -v  1>>build.log 2>&1

echo  "" >> build.log
file $PYTHON >> build.log
file `which gcc` >> build.log
echo  "" >> build.log

gcc -o gettime gettime.c

pyinstaller -F -n sagent-3000ns agent.py
mv dist/sagent-3000ns dist/sagent-3000-ns

mkdir -p $targetname
chmod u+x agent-daemon.sh
chmod u+x install.sh
chmod u+x install_all.sh
chmod u+x uninstall.sh
chmod u+x license_install.sh
chmod u+x config_install.sh
chmod u+x uninstall_config.sh
chmod u+x $ARCH/get-machine-id
chmod u+x $ARCH/gawk
chmod u+x $ARCH/netstat
chmod u+x $ARCH/ifconfig

cp  install.sh  ./$targetname
cp install_all.sh ./$targetname
cp  $targetfiles ./dist

cp -r $ARCH/* ./dist
cp -r session-bashrc ./dist

$PYTHON ./lib_enc.py ./dist/liblicense.so ./dist/liclibsign

cd dist
tar cvf ../$targetname/dist.tar *
cd ..

tarball="$targetname-$time.tar.gz"
tar czf $tarball $targetname

rm -rf build dist *.spec dist.tar