#!/bin/bash

install_dir=/usr/local/sagent-3000-ns
cd $install_dir

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

if grep '^[[:digit:]]*$' <<< "$VER";then
    if [ ! -f $install_dir/.osinfo ];then
        touch $install_dir/.osinfo
    fi
    echo "$OS-$VER" > $install_dir/.osinfo
else
    echo -e "\033[31m OS version is not digit. \033[0m"
    exit 1
fi

if [ $VER -gt 7 ] || [ $VER -lt 5 ];then
    echo -e "\033[31m Current system is not supported ! \033[0m"
    exit 1
fi

SESSION_BASHRC="session-bashrc/session-bashrc-6"
BASHRC_FILE=""
#if [[ $OS == "RedHat"* ]] || [[ $OS == "CentOS"* ]]
if echo "$OS" | grep -qwi "redhat" || echo "$OS" | grep -qwi "centos"
then
    SESSION_BASHRC="session-bashrc/session-bashrc-"$VER
    BASHRC_FILE="/etc/bashrc"
#elif [[ $OS == "Red Hat"* ]]
elif echo "$OS" | grep -qwi "red hat"
then
    SESSION_BASHRC="session-bashrc/session-bashrc-"$VER
    BASHRC_FILE="/etc/bashrc"
#elif [[ $OS == "Debian"* ]] || [[ $OS == "Ubuntu"* ]]
elif echo "$OS" | grep -qwi "Debian" || echo "$OS" | grep -qwi "Ubuntu"
then
    SESSION_BASHRC="session-bashrc/session-bashrc-ubuntu10"
    BASHRC_FILE="/etc/bash.bashrc"
else
    echo "The corresponding version was not found, and the current system is not supported for the time being."
    exit 0
fi


cp $SESSION_BASHRC $install_dir/session_bashrc
cp session-bashrc/csh.cshrc $install_dir
if [ ! -f $install_dir/session_user ];then
    echo "Please create session_user file!"
    exit 1
fi

users=`cat $install_dir/session_user | awk -F '=' '{print $2}'`
i=0
while read line
do
    passwd_user=`echo $line | awk -F':' '{print $1}'`
    for user in $users
    do
        if [[ $passwd_user == $user ]];then
            user_shell=`echo $line | awk -F':' '{print $NF}'`
            user_dir=`echo $line | awk -F':' '{print $6}'`
            user_arr[$i]=$user-$user_dir-$user_shell
            i=$(($i+1))
        fi
    done
done < /etc/passwd

old_ifs=$IFS
IFS=""
for aa in ${user_arr[@]};do
     shell_type=`echo $aa | awk -F '-' '{print $3}'`
     if [[ $shell_type =~ "bash" ]];then
        user_dir=`echo $aa | awk -F '-' '{print $2}'`
        if [ ! -f $user_dir/.bashrc ];then
            echo $user_dir" cannot find .bashrc file!"
            continue
        fi
        result=`cat $user_dir/.bashrc | grep "#NS-5000-AGENT"`
        if [ $? -ne 0 ];then
            cp $user_dir/.bashrc $user_dir/.bashrc.org~
            echo "#NS-5000-AGENT" >> $user_dir/.bashrc
            echo "source $install_dir/session_bashrc" >> $user_dir/.bashrc
            echo "NARI agent modify $user_dir/.bashrc file"
        fi
     elif [[ $shell_type =~ "csh" ]];then
        user_dir=`echo $aa | awk -F '-' '{print $2}'`
        if [ ! -f $user_dir/.cshrc ];then
            echo $user_dir" cannot find .cshrc file!"
            continue
        fi
        result=`cat $user_dir/.cshrc | grep "#NS-5000-AGENT"`
        if [ $? -ne 0 ];then
            cp $user_dir/.cshrc $user_dir/.cshrc.org~
            echo "#NS-5000-AGENT" >> $user_dir/.cshrc
            echo "source $install_dir/csh.cshrc" >> $user_dir/.cshrc
            echo "NARI agent modify $user_dir/.cshrc file"
        fi
     fi
done

IFS=$old_ifs

#gettime
chmod 555 gettime
cp gettime /usr/bin/

#ssh
chmod 755 ssh-ns
path=`which ssh`
real_path=`dirname $path`
if [ ! -f "$real_path/ssh-op" ];then
	mv $path $real_path/ssh-op
	echo "mv $path $real_path/ssh-op"
fi
cp ssh-ns $real_path/ssh
echo "cp ssh-ns $real_path/ssh"

#sftp
chmod  755 sftp-ns
path=`which sftp`
real_path=`dirname $path`
if [ ! -f "$real_path/sftp-op" ];then
	mv $path $real_path/sftp-op
	echo "mv $path $real_path/sftp-op"
fi
cp sftp-ns $real_path/sftp
echo "cp sftp-ns $real_path/sftp"

#scp
chmod  755 scp-ns
path=`which scp`
real_path=`dirname $path`
if [ ! -f "$real_path/scp-op" ];then
	mv $path $real_path/scp-op
	echo "mv $path $real_path/scp-op"
fi
cp scp-ns $real_path/scp
echo "cp scp-ns $real_path/scp"

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
    echo "NARI agent modify $RCLOCAL_FILE file"
    chmod +x $RCLOCAL_FILE
fi

modprobe ipmi_devintf

exit 0

