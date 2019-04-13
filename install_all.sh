#!/bin/bash

install_dir=/usr/local/sagent-3000-ns
dir=`dirname "$0"`
cd $dir
cur_dir=`pwd`

if [ ! -d "$install_dir" ];then
    mkdir -p "$install_dir"
fi

cd "$install_dir"
tar xvf "$cur_dir"/dist.tar

#copy awk
chmod 755 gawk
if [ ! -f /bin/gawk ]
then
    cp gawk /bin/
fi

if [ ! -f /usr/bin/awk ]
then
    ln -s /bin/gawk /usr/bin/awk
fi

source $install_dir/os_detect.sh
if [ $? -ne 0 ];then
    exit
fi
VER=${VER%%.*}

SESSION_BASHRC="session-bashrc/session-bashrc-6"
BASHRC_FILE=""
if [[ $OS == "RedHat"* ]] || [[ $OS == "CentOS"* ]]
then
    SESSION_BASHRC="session-bashrc/session-bashrc-"$VER
    BASHRC_FILE="/etc/bashrc"
elif [[ $OS == "Red Hat"* ]]
then
    SESSION_BASHRC="session-bashrc/session-bashrc-"$VER
    BASHRC_FILE="/etc/bashrc"
elif [[ $OS == "Debian"* ]] || [[ $OS == "Ubuntu"* ]]
then
    SESSION_BASHRC="session-bashrc/session-bashrc-ubuntu10"
    BASHRC_FILE="/etc/bash.bashrc"
else
    echo "The corresponding version was not found, and the current system is not supported for the time being."
    exit 0
    #SESSION_BASHRC="session-bashrc/session-bashrc-ubuntu10"
    #BASHRC_FILE="/etc/bash.bashrc"
fi

IFS=""
#bashrc
mv $SESSION_BASHRC $install_dir/session_bashrc
result=`cat $BASHRC_FILE | grep "#NS-5000-AGENT"`
if [ $? -ne 0 ];then
    cp $BASHRC_FILE $BASHRC_FILE.org~
    echo "#NS-5000-AGENT" >> $BASHRC_FILE
    echo "source $install_dir/session_bashrc" >> $BASHRC_FILE
fi

#csh
cp session-bashrc/csh.cshrc $install_dir
if [ -f /etc/csh.cshrc ];then
    result=`cat /etc/csh.cshrc | grep "#NS-5000-AGENT"`
    if [ $? -ne 0 ];then
        cp /etc/csh.cshrc /etc/csh.cshrc.org~
        echo "#NS-5000-AGENT" >> /etc/csh.cshrc
        echo "source $install_dir/csh.cshrc" >> /etc/csh.cshrc
    fi
fi

#delete session-bashrc directory
if [ -d "$install_dir/session-bashrc/" ];then
    rm -rf $install_dir/session-bashrc/
fi

#gettime
chmod 555 gettime
cp gettime /usr/bin/

#ssh
chmod 755 ssh-ns
path=`which ssh`
real_path=`dirname $path`
if [ ! -f "$real_path/ssh-op" ];then
	mv $path $real_path/ssh-op
fi
cp ssh-ns $real_path/ssh

#sftp
chmod  755 sftp-ns
path=`which sftp`
real_path=`dirname $path`
if [ ! -f "$real_path/sftp-op" ];then
	mv $path $real_path/sftp-op
fi
cp sftp-ns $real_path/sftp

#scp
chmod  755 scp-ns
path=`which scp`
real_path=`dirname $path`
if [ ! -f "$real_path/scp-op" ];then
	mv $path $real_path/scp-op
fi
cp scp-ns $real_path/scp

cp agent_public.key /etc/.agent_public.key
chmod 644 /etc/.agent_public.key
chmod +x get-machine-id
chmod +x os_detect.sh
chmod +x netstat
chmod +x ifconfig

rpm -ivh freeipmi*rpm

mkdir -p /tmp/.record
chmod 777 /tmp/.record
chmod a+t /tmp/.record

mkdir -p /tmp/.record/local
chmod 777 /tmp/.record/local
chmod a+t /tmp/.record/local

mkdir -p /tmp/.record/ssh
chmod 777 /tmp/.record/ssh
chmod a+t /tmp/.record/ssh

mkdir -p /tmp/.record/x11
chmod 777 /tmp/.record/x11
chmod a+t /tmp/.record/x11


if [ ! -d license ];then
    mkdir license
fi

if [ -f "/etc/rc.d/rc.local" ]
then
    RCLOCAL_FILE="/etc/rc.d/rc.local"
elif [ -f "/etc/rc.local" ]
then
    RCLOCAL_FILE="/etc/rc.local"
else
    echo "failed to set auto startup."
    exit 1
fi

flag=0
cat $RCLOCAL_FILE |grep "^exit 0" 2>&1 1>/dev/null
if [ $? -eq 0 ];then
    flag=1
fi
cat $RCLOCAL_FILE |grep "^cd $install_dir; ./agent-daemon.sh &" 2>&1 1>/dev/null
if [ $? -ne 0 ];then
    if [ $flag -eq 1 ];then
        sed -i '/^exit 0/d' $RCLOCAL_FILE
        echo "cd $install_dir; ./agent-daemon.sh &" >> $RCLOCAL_FILE
        echo "exit 0" >> $RCLOCAL_FILE
    else
        echo "cd $install_dir; ./agent-daemon.sh &" >> $RCLOCAL_FILE
    fi
    chmod +x $RCLOCAL_FILE
fi

modprobe ipmi_devintf

exit 0
