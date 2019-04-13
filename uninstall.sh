#/bin/bash

install_dir=/usr/local/sagent-3000-ns

#kill agent process
agent_num=`ps -ef | grep sagent-3000-ns | wc -l`
if [ $agent_num -gt 1 ];then
    ps -efww|grep -w 'sagent-3000-ns' |grep -v grep|cut -c 9-15|xargs kill -9
fi

#kill daemon process
daemon_num=`ps -ef | grep agent-daemon | wc -l`
if [ $daemon_num -gt 1 ];then
    ps -efww|grep -w 'agent-daemon' |grep -v grep|cut -c 9-15|xargs kill -9
fi

#script recording screen
flag=0
script_num=`ps -ef | grep script | grep "/tmp/.record/" | grep -v grep | wc -l`
if [ $script_num -gt 0 ];then
    flag=1
fi

#delete cmd and echo directory
tmp_dir=/tmp/.record
if [ -d $tmp_dir ];then
    rm -rf $tmp_dir
fi

#delete cmd and echo directory
if [ -f "/etc/rc.d/rc.local" ]
then
    RCLOCAL_FILE="/etc/rc.d/rc.local"
elif [ -f "/etc/rc.local" ]
then
    RCLOCAL_FILE="/etc/rc.local"
else
    #debian9
    RCLOCAL_FILE="/etc/rc.local"
fi

cat $RCLOCAL_FILE |grep "^cd $install_dir; ./agent-daemon.sh &" 2>&1 1>/dev/null
if [ $? -eq 0 ];then
    sed -i '/^cd \/usr\/local\/sagent-3000-ns; .\/agent-daemon.sh &/d' $RCLOCAL_FILE
fi

#delete installation directory
if [ -d $install_dir ];then
    rm -rf $install_dir
fi

#recover ssh
path=`which ssh`
real_path=`dirname $path`
if [ -f $real_path/ssh-op ];then
    mv $real_path/ssh-op $real_path/ssh
fi

#delete gettime
if [ -f /usr/bin/gettime ];then
    rm -rf /usr/bin/gettime
fi

#recover sftp
unalias sftp >/dev/null 2>&1

#recover scp
unalias scp >/dev/null 2>&1

#recover bashrc
if [ -f "/etc/bashrc" ];then
    BASHRC_FILE="/etc/bashrc"
elif [ -f "/etc/bash.bashrc" ];then
    BASHRC_FILE="/etc/bash.bashrc"
else
    exit 1
fi

if [ -f ${BASHRC_FILE}.org~ ];then
    rm -rf $BASHRC_FILE.org~
fi

cat $BASHRC_FILE | grep "^source /usr/local/sagent-3000-ns/session_bashrc" 2>&1 1>/dev/null
if [ $? -eq 0 ];then
    sed -i '/^#NS-5000-AGENT/d' $BASHRC_FILE
    sed -i '/^source \/usr\/local\/sagent-3000-ns\/session_bashrc/d' $BASHRC_FILE
fi

#recover csh.cshrc
if [ -f /etc/csh.cshrc ];then
    cat /etc/csh.cshrc | grep "^source /usr/local/sagent-3000-ns/csh.cshrc" 2>&1 1>/dev/null
    if [ $? -eq 0 ];then
        sed -i '/^#NS-5000-AGENT/d' /etc/csh.cshrc
        sed -i '/^source \/usr\/local\/sagent-3000-ns\/csh.cshrc/d' /etc/csh.cshrc
    fi
fi

if [ -f /etc/csh.cshrc.org~ ];then
    rm -rf /etc/csh.cshrc.org~
fi

if [ $flag -eq 1 ];then
    echo -e "\033[31m uninstall successfully! Please close this terminal and open another terminal to use normally! \033[0m"
else
    echo -e "\033[32m uninstall successfully! Thanks for using! \033[0m"
fi
