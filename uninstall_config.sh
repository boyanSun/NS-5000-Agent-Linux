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

#script Recording screen
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

#delete auto start
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

for aa in ${user_arr[@]};do
     shell_type=`echo $aa | awk -F '-' '{print $3}'`
     if [[ $shell_type =~ "bash" ]];then
        user_dir=`echo $aa | awk -F '-' '{print $2}'`
        if [ ! -f $user_dir/.bashrc ];then
            continue
        fi
        result=`cat $user_dir/.bashrc | grep "^source /usr/local/sagent-3000-ns/session_bashrc"`
        if [ $? -eq 0 ];then
            sed -i '/^#NS-5000-AGENT/d' $user_dir/.bashrc
            sed -i '/^source \/usr\/local\/sagent-3000-ns\/session_bashrc/d' $user_dir/.bashrc
        fi
        if [ -f $user_dir/.bashrc.org~ ];then
            rm -rf $user_dir/.bashrc.org~
        fi
     elif [[ $shell_type =~ "csh" ]];then
        user_dir=`echo $aa | awk -F '-' '{print $2}'`
        if [ ! -f $user_dir/.cshrc ];then
            continue
        fi
        result=`cat $user_dir/.cshrc | grep "^source /usr/local/sagent-3000-ns/csh.cshrc"`
        if [ $? -eq 0 ];then
            sed -i '/^#NS-5000-AGENT/d' $user_dir/.cshrc
            sed -i '/^source \/usr\/local\/sagent-3000-ns\/csh.cshrc/d' $user_dir/.cshrc
        fi
        if [ -f $user_dir/.cshrc.org~ ];then
            rm -rf $user_dir/.cshrc.org~
        fi
     fi
done

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

if [ $flag -eq 1 ];then
    echo -e "\033[31m uninstall successfully! Please close this terminal and open another terminal to use normally! \033[0m"
else
    echo -e "\033[32m uninstall successfully! Thanks for using! \033[0m"
fi
