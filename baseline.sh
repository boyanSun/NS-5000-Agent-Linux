#!/bin/bash

function fun_deny_unlock {
        oldIFS=$IFS
        IFS=$'\n'

#       echo open file "/etc/pam.d/$1"
        for line in $(cat /etc/pam.d/$1)
        do
                if [ `echo $line | grep -v ^[[:space:]]*# | grep '/^[[:space:]]*auth[[:space:]]*required[[:space:]]*(pam_tally.so|pam_tally2.so)[[:space:]]*deny=[0-9]*[[:space:]]*unlock_time=[0-9]*[[:space:]]*'` ]
                then
                        pam_moudle=`echo $line | awk '{print $3}'`

                        lib_exist=` find / -name $pam_moudle 2> null`

                        if [ -z "$lib_exist" ]
                        then
                                result=1
				#deny=0
				#unlock_time=0
                                #echo "can't find the moudle $pam_moudle"
                                break
                        fi
			
				#echo pam_moudle=$pam_moudle

                        deny=`echo $line | awk '{print $4}'| cut -f2 -d '='`
                        #echo deny=$deny

                        unlock_time=`echo $line | awk '{print $5}'| cut -f2 -d '='`
                        #echo unlock_time=$unlock_time
			break

                elif [ `echo $line | grep -v ^[[:space:]]*# | grep '/^[[:space:]]*auth[[:space:]]*(include|substack)[[:space:]]*.*'` ]
                then
                        name=`echo $line|awk '{print $3}'`
                        fun_deny_unlock $name
                fi
        done
	
}

function fun_1 {
        for excute in login sshd gdm
        do
		result=0
		pam_moudle=Null
		deny=0
		unlock_time=0
                #echo the program $excute:
        	fun_deny_unlock $excute
		#echo -e "\tpam_moudle=$pam_moudle"
		#echo -e "\tdeny=$deny"
		#echo -e "\tunlock_time=$unlock_time"
			if [ $result -eq 0  ]&&[ $deny -eq 5 ]&&[ $unlock_time -ge 120 ]
			then
				flag=1
			else
				flag=0
				break
			fi
        done
	if [ $flag -eq 1 ]
	then
		echo yes
	else
		echo no
	fi

	IFS=$oldIFS
	unset oldIFS line deny unlock_time name pam_moudle lib_exist result flag
}

code[1]="function fun_deny_unlock {
        oldIFS=\$IFS
        IFS=\$'\\\n'

#       echo open file \"/etc/pam.d/\$1\"
        for line in \$(cat /etc/pam.d/\$1)
        do
                if [ \`echo \$line | grep -v ^[[:space:]]*# | gawk '/^[[:space:]]*auth[[:space:]]*required[[:space:]]*(pam_tally.so|pam_tally2.so)[[:space:]]*deny=[0-9]*[[:space:]]*unlock_time=[0-9]*[[:space:]]*$/{print \$0}'\` ]
                then
                        pam_moudle=\`echo \$line \| awk '{print \$3}'\`
                        echo pam_moudle=\$pam_moudle

                        deny=\`echo \$line \| awk '{print \$4}'| cut -f2 -d '='\`
                        echo deny=\$deny

                        unlock_time=\`echo \$line | awk '{print \$5}'| cut -f2 -d '='\`
                        echo unlock_time=\$unlock_time

                        lib_exist=\` find \/ -name \$pam_moudle 2\> null\`
                        echo lib_exist is \$lib_exist

                        if test \"\$lib_exist\"
                        then
                                echo find the moudle \$pam_moudle
                                break
                        else
                                result=-2
                                echo can\'t find the moudle \$pam_moudle
                                break
                        fi

                elif [ \`echo \$line \| grep -v ^[[:space:]]*# | gawk '/^[[:space:]]*auth[[:space:]]*(include|substack)[[:space:]]*.*$/{print \$0}'\` ]
                then
                        name=\`echo \$line|awk '{print \$3}'\`
                        fun_deny_unlock \$name
                fi
        done
}

function fun_1 {
        for excute in login sshd gdm
        do
                echo the program \$excute:
                fun_deny_unlock \$excute
        done
}"

function fun_2 {
	#find / -type f -perm /u+s,g+s 2> /dev/null | ls -l
	for  PART  in `grep -v ^# /etc/fstab | awk '($6 != "0") {print $2 }'`
        do
            find $PART -type f \( -perm -04000 -o -perm -02000 \)  -xdev -exec ls -lg {} \; 2>>/dev/null >/dev/null
        done
	#ls -l $search
	echo yes
}

code[2]="for  PART  in `grep -v ^# /etc/fstab | awk '(\$6 != "0") {print \$2 }'`
        do
            find \$PART -type f \( -perm -04000 -o -perm -02000 \)  -xdev -exec ls -lg {} \; 2>>/dev/null
        done"

function fun_3 {
	timeout=0

	oldIFS=$IFS
	IFS=$'\n'
	for line in `cat /etc/profile`
	do
        	if [ -n "`echo $line | grep '/^[[:space:]]*(export)?[[:space:]]*TMOUT=[0-9]*[[:space:]]*'`" ]
        	then
                	timeout=`echo $line | cut -f2 -d '='`
        	fi
	done
	if [ $timeout -eq 600 ]
	then	
		echo yes
	else	
		echo no
	fi
	#echo timeout=$timeout
	IFS=$oldIFS
	
	unset timeout oldIFS line
}

code[3]="timeout=NULL

        for line in \`cat /etc/profile\`
        do
                if [ -n \"\`echo \$line | gawk '/^[[:space:]]*(export)?[[:space:]]*TMOUT=[0-9]*[[:space:]]*$/{print \$0}'\`\" ]
                then
                        timeout=\`echo \$line | cut -f2 -d \'=\'\`
                fi
        done
        echo timeout=\$timeout"

function fun_4 {
	ssh_PermitRootLogin=1
	protocol_num=0
	if [ -s /etc/ssh/sshd_config ]
	then
        	if [[ `cat /etc/ssh/sshd_config | grep '/[[:space:]]*PermitRootLogin[[:space:]]*yes[[:space:]]*'` ]]
        	then
                	ssh_PermitRootLogin=0
        	fi

		if [[ `cat /etc/ssh/sshd_config | grep '/[[:space:]]*Protocol[[:space:]]*2[[:space:]]*'` ]]
		then
			protocol_num=2
		fi
	fi

	if [ $ssh_PermitRootLogin -eq 1 ] && [ $protocol_num -eq 2 ]
	then
		echo yes
	else
		echo no
	fi

	unset ssh_PermitRootLogin protocol_num
}

code[4]="ssh_PermitRootLogin=1
	protocol_num=0

        if [ -s /etc/ssh/sshd_config ]
        then
                if [[ \`cat /etc/ssh/sshd_config | grep '/^[[:space:]]*PermitRootLogin[[:space:]]*yes[[:space:]]*'\` ]]
                then
                        ssh_PermitRootLogin=0
                fi
		if [[ \`cat /etc/ssh/sshd_config | grep '/^[[:space:]]*Protocol[[:space:]]*2[[:space:]]*'\` ]]
		then
			protocol_num=2
		fi
	fi
	if [ \$ssh_PermitRootLogin -eq 1 ] && [ \$protocol_num -eq 2 ]
	then
		echo yes
	else
		echo no
	fi"

function fun_5 {
	ssh_status=`ps -ef | grep sshd | grep -v grep`
	if [[ -z "$ssh_status" ]]
	then
        	ssh_running=0
	else
        	ssh_running=1
	fi
	telnet_status=`ps -ef | grep telnet | grep -v grep`
	if [[ -z "$telnet_status" ]]
	then
        	telnet_running=1
	else
        	telnet_running=0
	fi

	if [ $ssh_running -eq 1 ] && [ $telnet_running -eq 1 ]
	then
		echo yes
	else
		echo no
	fi
	unset ssh_running ssh_status 
}

code[5]="ssh_status=\`ps -ef | grep sshd | grep -v grep\`
	if [[ -z \"\$ssh_status\" ]]
	then
        	ssh_running=0
	else
        	ssh_running=1
	fi
	telnet_status=\`ps -ef | grep telnet | grep -v grep\`
	if [[ -z \"\$telnet_status\" ]]
	then
        	telnet_running=1
	else
        	telnet_running=0
	fi

	if [ \$ssh_running -eq 1 ] && [ \$telnet_running -eq 1 ]
	then
		echo yes
	else
		echo no
	fi
	unset ssh_running ssh_status "

function fun_6 {
	find / -maxdepth 3 -name .netrc 2>/dev/null
	find / -maxdepth 3 -name .rhosts 2>/dev/null
	find / -maxdepth 3 -name hosts.equiv 2>/dev/null
	totalNum_netrc=`find / -maxdepth 3 -name .netrc 2>/dev/null|wc -l`
	totalNum_rhosts=`find / -maxdepth 3 -name .rhosts 2>/dev/null|wc -l`
	totalNum_hosts_equiv=`find / -maxdepth 3 -name hosts.equiv 2>/dev/null|wc -l`
	
	#echo totalNum_netrc=$totalNum_netrc totalNum_rhosts=$totalNum_rhosts totalNum_hosts.equiv=$totalNum_hosts_equiv
	if [ $totalNum_netrc -eq 0 ] && [ $totalNum_rhosts -eq 0 ] && [ $totalNum_hosts_equiv -eq 0 ]
	then	
		echo yes
	else	
		echo no
	fi
	unset totalNum_netrc totalNum_rhosts totalNum_hosts_equiv
}

code[6]="find / -maxdepth 3 -name .netrc 2>/dev/null
        find / -maxdepth 3 -name .rhosts 2>/dev/null
        find / -maxdepth 3 -name hosts.equiv 2>/dev/null
        echo \"totalNum_netrc=\"\`find / -maxdepth 3 -name .netrc 2>/dev/null|wc -l\`
        echo \"totalNum_rhosts=\"\`find / -maxdepth 3 -name .rhosts 2>/dev/null|wc -l\`
        echo \"totalNum_hosts.equiv=\"\`find / -maxdepth 3 -name hosts.equiv 2>/dev/null|wc -l\`"

function fun_7 {
	umask1=`cat /etc/profile | grep "^umask" | grep -v ^# | awk '{print $2}'`	
	if [[ $umask1 -eq 027 ]]
	then	
		echo yes
	else
		echo no
	fi
	unset umask1
}

code[7]="umask1=\`cat /etc/profile | grep \"^umask\" | grep -v ^# | awk '{print \$2}'\`
	
	if [[ \$umask1 -eq 027 ]]
	then	
		echo yes
	else
		echo no
	fi
	unset umask1"

function fun_8 {
	if [[ -f /etc/passwd ]]
	then
        	file_passwd=`ls -l /etc/passwd | awk '{print $1}'`
		char1=${file_passwd:0-1:1}
		if [[ $char1 = "x" ]]
		then
			num1=1
		else
			num1=0
		fi
		char2=${file_passwd:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_passwd:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi	
		char4=${file_passwd:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_passwd:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_passwd:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_passwd:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_passwd:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_passwd:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		passwd_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	passwd_num=777
	fi
	#echo file_passwd=$passwd_num
	unset file_passwd char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9

	if [ -f /etc/shadow ]
	then
        	file_shadow=`ls -l /etc/shadow | awk '{print $1}'`
		char1=${file_shadow:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_shadow:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_shadow:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_shadow:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_shadow:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_shadow:0-6:1}
		if [[ $char1 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_shadow:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_shadow:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_shadow:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		shadow_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	shadow_num=777
	fi
	#echo file_shadow=$shadow_num
	unset file_shadow char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9

	if [ -f /etc/group ]
	then
        	file_group=`ls -l /etc/group | awk '{print $1}'`
		char1=${file_group:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_group:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_group:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_group:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_group:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_group:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_group:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_group:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_group:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		group_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	group_num=777
	fi
	#echo file_group=$group_num
	unset file_group char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9

	if [ $passwd_num -le 644 ]&&[ $shadow_num -le 600 ]&&[ $group_num -le 644 ]
	then
		echo yes
	else
		echo no
	fi
	unset group_num shadow_num group_num
#	if [ -f /etc/securetty ]
#	then
#       	file_securetty=`ls -l /etc/securetty | awk '{print $1}'`
#	else
#        	file_securetty=NULL
#	fi
#	echo file_securetty=$file_securetty
#	unset file_securetty

#	if [ -f /etc/services ]
#	then
#        	file_services=`ls -l /etc/services | awk '{print $1}'`
#	else
#        	file_services=NULL
#	fi
#	echo file_services=$file_services
#	unset file_services

#	if [ -f /etc/xinetd.conf ]
#	then
#        	file_xinetd_conf=`ls -l /etc/xinetd.conf | awk '{print $1}'`
#	else
#        	file_xinetd_conf=NULL
#	fi
#	echo file_xinetd_conf=$file_xinetd_conf
#	unset file_xinetd_conf

#	if [ -f /etc/grub.conf ]
#	then
#        	file_grub_conf=`ls -l /etc/grub.conf | awk '{print $1}'`
#	else
#       	file_grub_conf=NULL
#	fi
#	echo file_grub_conf=$file_grub_conf
#	unset file_grub_conf

#	if [ -f /etc/lilo.conf ]
#	then
#        	file_lilo_conf=`ls -l /etc/lilo.conf 2>/dev/null | awk '{print $1}'`
#	else
#        	file_lilo_conf="NULL"
#	fi
#	echo file_lilo_conf=$file_lilo_conf
#	unset file_lilo_conf
}

code[8]="if [ -f /etc/passwd ]
        then
                file_passwd=\`ls -l /etc/passwd | awk '{print \$1}'\`
        else
                file_passwd=NULL
        fi
        echo file_passwd=\$file_passwd
        unset file_passwd

        if [ -f /etc/shadow ]
        then
                file_shadow=\`ls -l /etc/shadow | awk '{print \$1}'\`
        else
                file_shadow=NULL
        fi
        echo file_shadow=\$file_shadow
        unset file_shadow

        if [ -f /etc/group ]
        then
                file_group=\`ls -l /etc/group | awk '{print \$1}'\`
        else
                file_group=NULL
        fi
        echo file_group=\$file_group
        unset file_group

        if [ -f /etc/securetty ]
	then
                file_securetty=\`ls -l /etc/securetty | awk '{print \$1}'\`
        else
                file_securetty=NULL
        fi
        echo file_securetty=\$file_securetty
        unset file_securetty

        if [ -f /etc/services ]
        then
                file_services=\`ls -l /etc/services | awk '{print \$1}'\`
        else
                file_services=NULL
        fi
        echo file_services=\$file_services
        unset file_services

        if [ -f /etc/xinetd.conf ]
        then
                file_xinetd_conf=\`ls -l /etc/xinetd.conf | awk '{print \$1}'\`
        else
                file_xinetd_conf=NULL
        fi
        echo file_xinetd_conf=\$file_xinetd_conf
        unset file_xinetd_conf

        if [ -f /etc/grub.conf ]
        then
                file_grub_conf=\`ls -l /etc/grub.conf | awk '{print \$1}'\`
	else
                file_grub_conf=NULL
        fi
        echo file_grub_conf=\$file_grub_conf
        unset file_grub_conf

        if [ -f /etc/lilo.conf ]
        then
                file_lilo_conf=\`ls -l /etc/lilo.conf 2>/dev/null | awk '{print \$1}'\`
        else
                file_lilo_conf=NULL
        fi
        echo file_lilo_conf=\$file_lilo_conf
        unset file_lilo_conf"

function fun_9 {
	passmax=`cat /etc/login.defs | grep '/^[[:space:]]*PASS_MAX_DAYS[[:space:]]*[0-9][0-9]*[[:space:]]*$' | awk '{print $2}'`
	passmin=`cat /etc/login.defs | grep '/^[[:space:]]*PASS_MIN_DAYS[[:space:]]*[0-9][0-9]*[[:space:]]*$' | awk '{print $2}'`
	passwarn=`cat /etc/login.defs | grep '/^[[:space:]]*PASS_WARN_AGE[[:space:]]*[0-9][0-9]*[[:space:]]*$' | awk '{print $2}'`
	
	#echo system_max_days=$passmax
	#echo system_min_days=$passmin
	#echo system_warn=$passwarn

	if [[ $passmax -le 90 ]] && [[ $passmin -eq 10 ]] && [[ $passwarn -eq 7 ]]
	then
		echo yes
	else
		echo no
	fi
#	oldIFS=$IFS
#	IFS=$'\n'
#	for line in $(cat /etc/shadow)
#	do
#       	tmp=$line
#        	if [ `echo $tmp | cut -d : -f2 | grep -v ^[\*\|!]` ]
#        	then
#                	username=`echo $tmp | cut -d : -f1`
#                	user_max_day=`echo $tmp | cut -d : -f5`
#                	echo "$username"="$user_max_day"
#        	fi
#	done
#	IFS=$oldIFS
#
#	unset oldIFS
#	unset line
#	unset tmp
#	unset username
#	unset user_max_day
	unset passmax passmin passwarn
}

code[9]="passmax=\`cat /etc/login.defs | grep '/^[[:space:]]*PASS_MAX_DAYS[[:space:]]*[0-9][0-9]*[[:space:]]*$' | awk '{print \$2}'\`
        echo system_max_days=\$passmax

        oldIFS=\$IFS
        IFS=$'\\\n'
        for line in \$(cat /etc/shadow)
        do
                tmp=\$line
                if [ \`echo \$tmp | cut -d : -f2 | grep -v ^[\*\|!]\` ]
                then
                        username=\`echo \$tmp | cut -d : -f1\`
                        user_max_day=\`echo \$tmp | cut -d : -f5\`
                        echo \"\$username\"=\"\$user_max_day\"
                fi
        done
        IFS=\$oldIFS

        unset line
        unset tmp
        unset username
        unset user_max_day
        unset passmax"

function fun_10 {
	count=0
	oldIFS=$IFS
	IFS=$'\n'

	for line in $(cat /etc/passwd)
	do
        	uid=`echo $line | cut -d : -f3`
        	if [ $uid -eq 0 ]
        	then
                	count=$(expr $count + 1)
        	fi
	done

	#echo $count

	if [ $count -le 1 ]
	then	
		echo yes
	else	
		echo no
	fi
	
	IFS=$oldIFS
	unset count line uid oldIFS
}

code[10]="count=0
        oldIFS=\$IFS
        IFS=$'\\\n'

        for line in \$(cat /etc/passwd)
        do
                uid=\`echo \$line | cut -d : -f3\`
                if [ \$uid -eq 0 ]
                then
                        count=\$(expr \$count + 1)
                fi
        done

        echo \$count

        IFS=\$oldIFS
        unset count
        unset line
        unset uid
        unset oldIFS"

function fun_11 {
	remember=NULL
	retry=0
	difork=NULL
	minlen=NULL
	ucredit=NULL
	lcredit=NULL
	dcredit=NULL
	ocredit=NULL

	if [[ $os_name = "rhel" ]] || [[ $os_name = "centos" ]] || [[ $os_name = "fedora" ]] || [[ $os_name = "kylin" ]]
	then
		remember_item=`cat /etc/pam.d/system-auth | gawk '/^[[:space:]]*password[[:space:]]*sufficient[[:space:]]*pam_unix\.so[[:space:]]*.*[[:space:]]*remember=(-)?(0|[1-9][0-9]*)[[:space:]]*.*$/{print $0}'`
		for item in $(echo $remember_item)
		do
			if [ -n "`echo $item | grep remember`" ]
			then
				remember=`echo $item | cut -f2 -d '='`
			fi
		done

		pam_cracklib=`cat /etc/pam.d/system-auth | gawk '/^[[:space:]]*password[[:space:]]*requisite[[:space:]]*pam_cracklib\.so[[:space:]]*/{print $0}'`
		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*retry=(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
		then
			for item in $(echo $pam_cracklib)
        		do
                		if [ -n "`echo $item | grep "retry="`" ]
                		then
                        		retry=`echo $item | cut -f2 -d '='`
                		fi
        		done
		fi

		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*difork=(-)?(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "difork="`" ]
                        	then
                                	difork=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*minlen=(-)?(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "minlen="`" ]
                        	then
                                	minlen=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*ucredit=(-)?(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "ucredit="`" ]
                        	then
                                	ucredit=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*lcredit=(-)?(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "lcredit="`" ]
                        	then
                                	lcredit=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*dcredit=(-)?(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "dcredit="`" ]
                        	then
                                	dcredit=`echo $item | cut -f2 -d '='`
                        	fi
                	done
       	 	fi

		if [ -n "`echo $pam_cracklib | gawk '/[[:space:]]*ocredit=(-)?(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "ocredit="`" ]
                        	then
                                	ocredit=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

	elif [[ $os_name = "debian" ]]||[[ $os_name = "ubuntu" ]]||[[ $os_name = "linux_mint" ]]	
	then
		remember_item=`cat /etc/pam.d/common-password | grep '/^[[:space:]]*password[[:space:]]*sufficient[[:space:]]*pam_unix\.so[[:space:]]*.*[[:space:]]*remember=(0|[1-9][0-9]*)[[:space:]]*.*$'`
        	for item in $(echo $remember_item)
        	do
                	if [ -n "`echo $item | grep remember`" ]
                	then
                        	remember=`echo $item | cut -f2 -d '='`
                	fi
        	done

        	pam_cracklib=`cat /etc/pam.d/common-password | grep '/^[[:space:]]*password[[:space:]]*requisite[[:space:]]*pam_cracklib\.so[[:space:]]*'`
        	if [ -n "`echo pam_cracklib | gawk '/[[:space:]]*retry=(0|[1-9][0-9]*)[[:space:]]*/{print $0}'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "retry="`" ]
                        	then
                                	retry=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi
	
		if [ -n "`echo $pam_cracklib | grep '/[[:space:]]*difork=(-)?(0|[1-9][0-9]*)[[:space:]]*'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "difork="`" ]
                        	then
                                	difork=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

        	if [ -n "`echo $pam_cracklib | grep '/[[:space:]]*minlen=(-)?(0|[1-9][0-9]*)[[:space:]]*'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "minlen="`" ]
                        	then
                                	minlen=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

        	if [ -n "`echo $pam_cracklib | grep '/[[:space:]]*ucredit=(-)?(0|[1-9][0-9]*)[[:space:]]*'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "ucredit="`" ]
				then
					ucredit=`echo $item | cut -f2 -d '='`
                        	fi
                	done
        	fi

        	if [ -n "`echo $pam_cracklib | grep '/[[:space:]]*lcredit=(-)?(0|[1-9][0-9]*)[[:space:]]*'`" ]
        	then
                	for item in $(echo $pam_cracklib)
                	do
                        	if [ -n "`echo $item | grep "lcredit="`" ]
                        	then
                                lcredit=`echo $item | cut -f2 -d '='`
                        fi
                done
        fi

        if [ -n "`echo $pam_cracklib | grep '/[[:space:]]*dcredit=(-)?(0|[1-9][0-9]*)[[:space:]]*'`" ]
        then
                for item in $(echo $pam_cracklib)
                do
                        if [ -n "`echo $item | grep "dcredit="`" ]
                        then
                                dcredit=`echo $item | cut -f2 -d '='`
                        fi
                done
        fi
	
	if [ -n "`echo $pam_cracklib | grep '/[[:space:]]*ocredit=(-)?(0|[1-9][0-9]*)[[:space:]]*'`" ]
        then
                for item in $(echo $pam_cracklib)
                do
                        if [ -n "`echo $item | grep "ocredit="`" ]
                        then
                                ocredit=`echo $item | cut -f2 -d '='`
                        fi
                done
        fi
fi

#echo remember=$remember
#echo retry=$retry
#echo difork=$difork
#echo minlen=$minlen
#echo ucredit=$ucredit
#echo lcredit=$lcredit
#echo dcredit=$dcredit
#echo ocredit=$ocredit

if [ $retry -eq 3 ] && [[ $dcredit = "-1" ]] && [[ $lcredit = "-1" ]] && [[ $ucredit = "-1" ]] && [[ $ocredit = "-1" ]]
then
	echo yes
else
	echo no
fi

unset remember
unset retry
unset difork
unset minlen
unset ucredit
unset lcredit
unset dcredit
unset ocredit
}

code[11]="remember=NULL
retry=NULL
difork=NULL
minlen=NULL
ucredit=NULL
lcredit=NULL
dcredit=NULL
ocredit=NULL

if [ \$os_name = \"rhel\" ] || [ \$os_name = \"centos\" ] || [ \$os_name = \"fedora\" ]
then
	echo \$os_name
	remember_item=\`cat /etc/pam.d/system-auth \| gawk '/^[[:space:]]*password[[:space:]]*sufficient[[:space:]]*pam_unix\.so[[:space:]]*.*[[:space:]]*remember=(0|[1-9][0-9]*)[[:space:]]*.*$/{print $0}'\`
	for item in \$(echo \$remember_item)
	do
		if [ -n \"\`echo \$item \| grep remember\`\" ]
		then
			remember=\`echo \$item | cut -f2 -d '='\`
		fi
	done

	pam_cracklib=\`cat /etc/pam.d/system-auth | gawk '/^[[:space:]]*password[[:space:]]*requisite[[:space:]]*pam_cracklib\.so[[:space:]]*/{print \$0}'\`
	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*retry=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
	then
		for item in \$(echo \$pam_cracklib)
        	do
                	if [ -n \"\`echo \$item | grep \"retry=\"\`\" ]
                	then
                        	retry=\`echo \$item | cut -f2 -d '='\`
                	fi
        	done
	fi

	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*difork=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"difork=\"\`\" ]
                        then
                                difork=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*minlen=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"minlen=\"\`\" ]
                        then
                                minlen=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*ucredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"ucredit=\"\`\" ]
                        then
                                ucredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*lcredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"lcredit=\"\`\" ]
                        then
                                lcredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*dcredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"dcredit=\"\`\" ]
                        then
                                dcredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*ocredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"ocredit=\"\`\" ]
                        then
                                ocredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

elif [ \$os_name = \"debian\" ]||[ \$os_name = \"ubuntu\" ]||[ \$os_name = \"linux_mint\" ]	
then
	remember_item=\`cat /etc/pam.d/common-password | gawk '/^[[:space:]]*password[[:space:]]*sufficient[[:space:]]*pam_unix\.so[[:space:]]*.*[[:space:]]*remember=(0|[1-9][0-9]*)[[:space:]]*.*$/{\print \$0}'\`
        for item in \$(echo \$remember_item)
        do
                if [ -n \"\`echo \$item | grep remember\`\" ]
                then
                        remember=\`echo \$item | cut -f2 -d '='\`
                fi
        done

        pam_cracklib=\`cat /etc/pam.d/common-password | gawk '/^[[:space:]]*password[[:space:]]*requisite[[:space:]]*pam_cracklib\.so[[:space:]]*/{print $0}'\`
        if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*retry=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"retry=\"\`\" ]
                        then
                                retry=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi
	
	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*difork=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"difork=\"\`\" ]
                        then
                                difork=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

        if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*minlen=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"minlen=\"\`\" ]
                        then
                                minlen=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

        if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*ucredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"ucredit=\"\`\" ]
			then
				ucredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

        if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*lcredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"lcredit=\"\`\" ]
                        then
                                lcredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi

        if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*dcredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"dcredit=\"\`\" ]
                        then
                                dcredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi
	
	if [ -n \"\`echo \$pam_cracklib | gawk '/[[:space:]]*ocredit=(0|[1-9][0-9]*)[[:space:]]*/{print \$0}'\`\" ]
        then
                for item in \$(echo \$pam_cracklib)
                do
                        if [ -n \"\`echo \$item | grep \"ocredit=\"\`\" ]
                        then
                                ocredit=\`echo \$item | cut -f2 -d '='\`
                        fi
                done
        fi
fi

echo remember=\$remember
echo retry=\$retry
echo difork=\$difork
echo minlen=\$minlen
echo ucredit=\$ucredit
echo lcredit=\$lcredit
echo dcredit=\$dcredit
echo ocredit=\$ocredit

unset remember
unset retry
unset difork
unset minlen
unset ucredit
unset lcredit
unset dcredit
unset ocredit"

function fun_12 {
	if [ `echo $PATH | grep '\.\/'` ]
	then
        	safty=no
	else
        	safty=yes
	fi

#	echo safty=$safty
	echo $safty
	unset safty
}

code[12]="if [ \`echo \$PATH | grep '\.\/'\` ]
then
        safty=yes
else
        safty=no
fi

echo safty=\$safty
unset safty"

function fun_13 {		
        oldIFS=$IFS
        IFS=$'\n'
	if [ -s /etc/syslog.conf ]
	then
		for line in $(cat /etc/syslog.conf)
		do
        	        if [ `echo $line | grep -v ^[[:space:]]*#` ]
        	        then
                	        kind=`echo $line | awk '{print $1}'`
                        	where=`echo $line | awk '{print $2}'`
	
        	                if [ `echo $where | grep ^@` ]
                	        then
                        		remote_syslog=yes
                                	IFS=';'
                                	for item in $kind
                               		do
                                        	#echo $item=$where
						misc=1
                	                done
					IFS=$'\n'
				else
					remote_syslog=no
				fi
			else
				remote_syslog=no
                        fi
		done
	fi
					
	if [ -s /etc/rsyslog.conf ]
	then
		for line in $(cat /etc/rsyslog.conf)
		do
                        if [ `echo $line | grep -v ^[[:space:]]*#` ]
                        then
                        	kind=`echo $line | awk '{print $1}'`
                        	where=`echo $line | awk '{print $2}'`
	
	                        if [ `echo $where | grep ^@` ]
	                        then
							
        	                        remote_syslog=yes
	                                IFS=';'
        	                	for item in $kind
                	               	do
                        	                #echo $item=$where
						misc=1
                                	done
					IFS=$'\n'
				else
					remote_syslog=no
				fi
			else
				remote_syslog=no
          		fi
		done
	fi
	IFS=$oldIFS
	echo $remote_syslog
	unset misc
}

code[13]="if [ -s /etc/sysconfig/syslog ]
then
	if [[ \`cat /etc/sysconfig/syslog | grep SYSLOGD_OPTIONS | grep '\-m'\` ]]
	then
		flag=1
	else
		remote_syslog=no
	fi
	
	if [[ \$flag = 1 ]]
	then
		line=\`cat /etc/services | grep syslog | grep -v .*-.* | awk '{print \$2}'\`
		if test \$line
		then
			if [ \`echo \$line | grep -v -x -E '[0-9]*/tcp|[0-9]*/udp'[[:space:]]*\` ]
			then
				flag=0
				remote_syslog=no
			fi
		else
			flag=0
			remote_syslog=no
		fi
	fi
	unset line
	
	if [[ \$flag = 1 ]]
	then
		oldIFS=\$IFS
		IFS=$'\\\n'
		for line in \$(cat /etc/syslog.conf)
		do
			if [ \`echo \$line | grep -v ^[[:space:]]*#\` ]
			then 
				kind=\`echo \$line | awk '{print \$1}'\`
				where=\`echo \$line | awk '{print \$2}'\`
				if [ \`echo \$where | grep ^@\` ]
				then
					remote_syslog=yes
				fi
			
				IFS=';'
				for item in \$kind
				do
					echo \$item=\$where 
				done
			fi
		done
	fi
	IFS=\$oldIFS
else
	remote_syslog=no
fi		
			
echo remote_syslog=\$remote_syslog"

function fun_14 {
	ssh_status=`ps -ef | grep sshd | grep -v grep`
	if [[ -z "$ssh_status" ]]
	then
		echo no
	else
		echo yes
	fi
	unset ssh_status
}

code[14]="ssh_status=\`ps -ef | grep sshd | grep -v grep\`
	if [[ -z \"\$ssh_status\" ]]
	then
		echo no
	else
		echo yes
	fi
	unset ssh_status"

function fun_15 {
	flag=1
	oldIFS=$IFS
	IFS=$'\n'

	for line in $(cat /etc/shadow)
	do
        	lock=`echo $line | cut -d \: -f2`
        	char=${lock:0:1}

        	if [[ $char == "*" ]] || [[ $char == "!" ]]
        	then
                	username=`echo $line | cut -d \: -f1`
                	#echo $username
					
					if [[ $username == "lp" ]] || [[ $username == "sync" ]] || [[ $username == "halt" ]] || [[ $username == "news" ]] || [[ $username == "uucp" ]] || [[ $username == "operator" ]] || [[ $username == "games" ]] || [[ $username == "gopher" ]] || [[ $username == "smmsp" ]] || [[ $username == "nfsnobody" ]] || [[ $username == "nobody" ]]
					then
						flag=0
						break
					fi
						
        	fi
	done
	
	if [ $flag -eq 0 ]
	then
		echo no
	elif [ $flag -eq 1 ]
	then	
		echo yes
	fi

	IFS=$oldIFS
	unset line
	unset char
	unset username flag
}

code[15]="oldIFS=\$IFS
IFS=$'\\\n'

for line in \$(cat /etc/shadow)
do
        lock=\`echo \$line | cut -d \: -f2\`
        char=\${lock:0:1}

        if [[ \$char == \"*\" ]] || [[ \$char == \"!\" ]]
        then
                username=\`echo \$line | cut -d \: -f1\`
                echo \$username=locked
        fi
done

IFS=\$oldIFS
unset line
unset char
unset username"

function fun_16 {
	if [[ -f /etc/passwd ]]
	then
        	file_passwd=`ls -l /etc/passwd | awk '{print $1}'`
		char1=${file_passwd:0-1:1}
		if [[ $char1 = "x" ]]
		then
			num1=1
		else
			num1=0
		fi
		char2=${file_passwd:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_passwd:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi	
		char4=${file_passwd:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_passwd:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_passwd:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_passwd:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_passwd:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_passwd:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		passwd_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	passwd_num=777
	fi
	#echo file_passwd=$passwd_num
	unset file_passwd char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9

	if [ -f /etc/shadow ]
	then
        	file_shadow=`ls -l /etc/shadow | awk '{print $1}'`
		char1=${file_shadow:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_shadow:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_shadow:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_shadow:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_shadow:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_shadow:0-6:1}
		if [[ $char1 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_shadow:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_shadow:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_shadow:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		shadow_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	shadow_num=777
	fi
	#echo file_shadow=$shadow_num
	unset file_shadow char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9

	if [ -f /etc/group ]
	then
        	file_group=`ls -l /etc/group | awk '{print $1}'`
		char1=${file_group:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_group:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_group:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_group:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_group:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_group:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_group:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_group:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_group:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		group_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	group_num=777
	fi
	#echo file_group=$group_num
	unset file_group char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9

	if [ -f /etc/services ]
	then
        	file_group=`ls -l /etc/services | awk '{print $1}'`
		char1=${file_group:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_group:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_group:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_group:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_group:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_group:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_group:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_group:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_group:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		service_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	service_num=777
	fi
	#echo file_group=$group_num
	unset file_service char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9
	if [ -f /etc/inetd.conf ]
	then
        	file_inetd=`ls -l /etc/inetd.conf | awk '{print $1}'`
		char1=${file_group:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_group:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_group:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_group:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_group:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_group:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_group:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_group:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_group:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		inetd_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	inetd_num=777
	fi
	#echo file_group=$group_num
	unset file_inetd char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9
	if [ -f /etc/security ]
	then
        	file_security=`ls -l /etc/security | awk '{print $1}'`
		char1=${file_group:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_group:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_group:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_group:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_group:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_group:0-6:1}
		if [[ $char6 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_group:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_group:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_group:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		security_num=$[($str3 * 100) + ($str2 * 10) + $str1]
	else
        	security_num=777
	fi
	#echo file_group=$group_num
	unset file_security char1 char2 char3 char4 char5 char6 char7 char8 char9 str1 str2 str3 num1 num2 num3 num4 num5 num6 num7 num8 num9
	
	if [ $passwd_num -le 644 ]&&[ $shadow_num -le 600 ]&&[ $group_num -le 644 ]&&[ $service_num -le 644 ]&&[ $inetd_num -le 600 ]&&[ $security_num -le 600 ]
	then
		echo yes
	else
		echo no
	fi
	unset group_num shadow_num group_num service_num inetd_num security_num
}

code[16]="oldIFS=\$IFS
IFS=$'\\\n'

for line in \$(cat /etc/passwd)
do
        username=\`echo \$line | cut -d : -f1\`
        gid=\`echo \$line | cut -d : -f4\`
        if [ \$gid -eq 0 ]
        then
                echo \"\$username\"_gid=0
        fi
done

IFS=\$oldIFS
unset line
unset gid
unset oldIFS"

function fun_17 {
	flag=0
	if [ -s /etc/syslog.conf ]
	then
        oldIFS=$IFS
        IFS=$'\n'
        for line in $(cat /etc/syslog.conf)
        do
            if [ `echo $line | grep -v ^[[:space:]]*# | grep '/^[[:space:]]*\*\.err\;kern\.debug\;daemon\.notice[[:space:]]*\/var\/adm\/messages[[:space:]]*/{print $0}'` ]
             then
                        	#kind=`echo $line | awk '{print $1}'`
                        	#where=`echo $line | awk '{print $2}'`

                        	#IFS=';'
                        	#for item in $kind
                        	#do
                            #    	echo $item=$where
                        	#done
                        	#IFS=$'\n'
				flag=1
            fi
        done

        IFS=$oldIFS
	elif [ -s /etc/rsyslog.conf ]
	then
		oldIFS=$IFS
        IFS=$'\n'
        for line in $(cat /etc/rsyslog.conf)
        do
            if [ `echo $line | grep -v ^[[:space:]]*# | grep '/^[[:space:]]*\*\.err\;kern\.debug\;daemon\.notice[[:space:]]*\/var\/adm\/messages[[:space:]]*'` ]
            then
				flag=1
            fi
        done

        IFS=$oldIFS
	fi
	if [ $flag -eq 0 ]
	then
		echo no
	elif [ $flag -eq 1 ]
	then	
		echo yes
	fi
	
	unset flag oldIFS line 
}

code[17]="if [ -s /etc/syslog.conf ]
        then
                oldIFS=\$IFS
                IFS=$'\\\n'
                for line in \$(cat /etc/syslog.conf)
                do
                        if [ \`echo \$line | grep -v ^[[:space:]]*#\` ]
                        then
                                kind=\`echo \$line | awk '{print \$1}'\`
                                where=\`echo \$line | awk '{print \$2}'\`

                                IFS=';'
                                for item in \$kind
                                do
                                        echo \$item=\$where
                                done
                                IFS=$'\\\n'
                        fi
                done

                IFS=\$oldIFS
        else
                echo syslog=NULL
        fi"

function fun_18 {
	flag=1
	oldIFS=$IFS
	IFS=$'\n'

	gid_min=`cat /etc/login.defs | grep '/^[[:space:]]*GID_MIN[[:space:]]*[[:digit:]]*[[:space:]]*' |awk '($1="GID_MIN") {print $2}'`
	gid_max=`cat /etc/login.defs | grep '/^[[:space:]]*GID_MAX[[:space:]]*[[:digit:]]*[[:space:]]*' |awk '($1="GID_MAX") {print $2}'`
	
	for line in $(cat /etc/passwd)
	do
        	gid=`echo $line | awk -F ':' '{print $4}'`
        	if [[ $gid -ge $gid_min ]] || [[ $gid -le $gid_max ]]
        	then
                	flag=1
            	else	
			flag=0
			break
        	fi
	done

	if [ $flag -eq 0 ]
	then
		echo no
	elif [ $flag -eq 1 ]
	then	
		echo yes
	fi
	unset gid condition line gid_min gid_max flag
	IFS=$oldIFS	
}

code[18]="oldIFS=\$IFS
        IFS=$'\\\n'

        for line in \$(cat /etc/passwd)
        do
                gid=\`echo \$line | awk -F ':' '{print \$4}'\`
                if [[ \$gid -ge 500 ]]
                then
                        condition=\`echo \$line | grep -v /sbin/nologin\`
                        if test \$condition
                        then
                                echo \`echo \$line | awk -F : '{print \$1}'\`=\$gid
                        fi
                fi
        done

        unset gid
        unset condition
        unset line
        IFS=\$oldIFS"

function fun_19 {
	ip_forward=`cat /proc/sys/net/ipv4/ip_forward`
	#echo ip_forward=$ip_forward
	
	if [ $ip_forward -eq 0 ]
	then
		echo yes
	else	
		echo no
	fi
	
	unset ip_forward
}

code[19]="ip_forward=\`cat /proc/sys/net/ipv4/ip_forward\`
        echo ip_forward=\$ip_forward

        unset ip_forward"

function fun_20 {
	oldIFS=$IFS
	IFS=$'\n'
	service=`ps -ef | grep nfs | grep -v grep`

	if test $service
	then
        NFS=1
        if [ -s /etc/hosts.allow ]
        then
            for line in $(cat /etc/hosts.allow)
            do
                if [ `echo $line | grep -v '^[[:space:]]*#'` ]
                then
                    item=`echo $line | awk -F ':' 'print $1'`
                    if [ `echo $item | grep -i all` ]||[ `echo $item | grep -i nfs` ]
                    then
                        echo $line
                    fi
                fi
            done
			NFS_allow=1
		else	
			NFS_allow=0
        fi

        if [ -s /etc/hosts.deny ]
        then
            for line in $(cat /etc/hosts.deny)
            do
                if [ `echo $line | grep -v '^[[:space:]]*#'` ]
                then
                    item=`echo $line | awk -F ':' 'print $1'`
                    if [ `echo $item | grep -i all` ]||[ `echo $item | grep -i nfs` ]
                    then
                        echo $line
                    fi
                fi
			done
			NFS_deny=1
		else
			NFS_deny=0
        fi
	else
		NFS=0
	fi

	#echo NFS=$NFS
	
	if [ $NFS -eq 1 ] && [ $NFS_allow -eq 1 ] && [ $NFS_deny -eq 1 ]
	then
		echo yes
	else
		echo no
	fi
	IFS=$oldIFS

	unset NFS line item service oldIFS NFS_allow NFS_deny
}

code[20]="oldIFS=\$IFS
        IFS=$'\\\n'
        service=\`ps -ef | grep nfs | grep -v grep\`

        if test \$service
        then
                NFS=1
                if [ -s /etc/hosts.allow ]
                then
                        for line in \$(cat /etc/hosts.allow)
                        do
                                if [ \`echo \$line | grep -v '^[[:space:]]*#'\` ]
                                then
                                        item=\`echo \$line | awk -F ':' 'print \$1'\`
                                        if [ \`echo \$item | grep -i all\` ]||[ \`echo \$item | grep -i nfs\` ]
                                        then
                                                echo \$line
                                        fi
                                fi
                        done
                fi

                if [ -s /etc/hosts.deny ]
		then
                        for line in \$(cat /etc/hosts.deny)
                        do
                                if [ \`echo \$line | grep -v '^[[:space:]]*#'\` ]
                                then
                                        item=\`echo \$line | awk -F ':' 'print \$1'\`
                                        if [ \`echo \$item | grep -i all\` ]||[ \`echo \$item | grep -i nfs\` ]
                                        then
                                                echo \$line
                                        fi
                                fi
                        done
                fi
        else
                NFS=0
        fi

        echo NFS=\$NFS
        IFS=\$oldIFS

        unset NFS
        unset line
        unset item
        unset service
        unset oldIFS"

function fun_21 {
	cat /etc/inittab > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		line=`cat /etc/inittab | grep '/^[[:space:]]*ca\:\:ctrlaltdel\:\/sbin\/shutdown \-r \-t 4 now[[:space:]]*'`
		if [[ -n \"\$line\" ]]
		then
			echo yes
		else
			echo no
		fi
	else
		echo yes
	fi
	
	unset line
}

code[21]="cat /etc/inittab > /dev/null 2>&1
	if [ \$? -eq 0 ]
	then
		line=\`cat /etc/inittab | grep '/^[[:space:]]*ca\:\:ctrlaltdel\:\/sbin\/shutdown \-r \-t 4 now[[:space:]]*'\`
		if [[ -n \"\$line\" ]]
		then
			echo yes
		else
			echo no
		fi
	else
		echo yes
	fi
	
	unset line"

function fun_22 {
	host_allow=`cat /etc/hosts.allow | grep -v "^[[:space:]]*#"`
	host_deny=`cat /etc/hosts.deny | grep -v "^[[:space:]]*#"`
	
	if [[ -n "$host_allow" ]] && [[ -n "$host_deny" ]]
	then
		echo yes
	else
		echo no
	fi
	
	unset host_allow host_deny
}

code[22]="cat /etc/hosts.allow | grep -v \"^[[:space]]*#\"

	cat /etc/hosts.deny | grep -v \"^[[:space]]*#\""

function fun_23 {
	num=`awk -F: '$2 == ""  { print $1 }' /etc/shadow | wc -l`
	
	if [ $num -eq 0 ]
	then
		echo yes
	else
		echo no
	fi
}

code[23]="awk -F: '$2 == \"\"  { print \$1 }' /etc/shadow"

function fun_24 {
	service=`ps -elf | grep ntp | grep -v grep`

	if test "$service"
	then
        ntp=1
		#echo ntp=$ntp
        	if [ -s /etc/ntp.conf ]
        	then
			oldIFS=$IFS
			IFS=$'\n'
			for line in $(cat /etc/ntp.conf)
			do
				if [ `echo $line | grep -v "^[[:space:]]*#" | grep ^[[:space:]]*server` ]
				then
					echo server=`echo $line | awk '{print $2}'`
				fi
			done

				if [ -z "$server" ]
				then
					server=0
				else
					server=1
				fi
        	else
                echo server=0
        	fi
	else
        ntp=0
	fi
	
	if [ $ntp -eq 1 ] && [ $server -eq 1 ]
	then
		echo yes
	else
		echo no
	fi
	IFS=$oldIFS
	unset ntp server service oldIFS
}

code[24]="service=\`ps -elf | grep ntp | grep -v grep\`

        if test \$service
        then
                ntp=1
                if [ -s /etc/ntp.conf ]
                then
                        server=\`cat /etc/ntp.conf | grep -v \"^[[:space:]]*#\" | grep ^[[:space:]]*server\`
                else
                        server=0
                fi
        else
                ntp=0
        fi

        echo ntp=\$ntp
        echo server=\$server

        unset ntp
        unset server
        unset service"

function fun_25 {
	net_redirect=`sysctl -n net.ipv4.conf.all.accept_redirects`
	if [ $net_redirect -eq 0 ]
	then
		echo yes
	else
		echo no
	fi
}

code[25]="net_redirect=\`sysctl -n net.ipv4.conf.all.accept_redirects\`"

function fun_26 {
	service=`ps -elf | grep snmp | grep -v grep`
	community_set=0
	if test $service
	then
        snmp=1
        #echo snmp=$snmp
        if [ -s /etc/snmpd.conf ]
        then
            #echo $snmp
                community=`cat /etc/snmpd.conf | grep -v "^[[:space:]]*#" | grep ^[[:space:]]*"rocommunity\|rwcommunity"`
                if test $community
                then
                    community_set=1
                else
                    community_set=0
                fi
        else
            community=0
        fi
	else
        snmp=0
	fi
	
	if [ $snmp -eq 1 ]&&[ $community_set -eq 1 ]
	then
		echo yes
	else
		echo no
	fi
	unset snmp community service community_set
}

code[26]="service=\`ps -elf | grep snmp | grep -v grep\`

if test \$service
then
        snmp=1
        echo snmp=\$snmp
        if [ -s /etc/snmpd.conf ]
        then
                echo \$snmp
                community=\`cat /etc/snmpd.conf | grep -v \"^[[:space:]]*#\" | grep ^[[:space:]]*\"rocommunity\|rwcommunity\"\`
                if test \$community
                then
                        echo \"\$community\"
                else
                        echo community=NULL
                fi
        else
                echo community=NULL
        fi
else
        snmp=0
        echo snmp=\$snmp
fi

unset snmp
unset community
unset service"

function fun_27 {
	type gconftool-2 >/dev/null 2>&1 || { echo no ;exit 1; }
	idle_delay=`gconftool-2 -R / | grep '/^[[:space:]]*idle_delay[[:space:]]*=[[:space:]]*[0-9]*[[:space:]]*$'`
	count=`gconftool-2 -R / | grep '/^[[:space:]]*idle_delay[[:space:]]*=[[:space:]]*[0-9]*[[:space:]]*$' | wc -l`
	count_1=0
	for element in $idle_delay
	do
		if [ "$element" -gt 0 ] 2>/dev/null ;then
	       #if grep '^[[:digit:]]*$' <<< "$element";then
	                if [[ $element -le 15 ]];then
	                        let "count_1+=1"
	                fi
	        fi
	done
	
	if [[ $count_1 -eq $count ]];then
	        echo yes
	else
	        echo no
	fi

	
	#if [[ $idle_delay -le 15 ]]
	#then
	#	echo yes
	#else
	#	echo no
	#fi
}

code[27]="gconftool-2 -R / | grep '/^[[:space:]]*idle_delay[[:space:]]*=[[:space:]]*[0-9]*[[:space:]]*$'"

function fun_28 {
	if [ -s /etc/syslog.conf ]
	then
        log=`cat /etc/syslog.conf | grep -v "^[[:space:]]*#" | grep '/^([[:space:]]*authpriv\.\*[[:space:]]*|[[:space:]]*authpriv\.info.*[[:space:]]*|[[:space:]]*\*\.\*[[:space:]]*)'`
		if [[ -n "$log" ]]
		then
			echo yes
		else
			echo no
		fi		
	fi

	if [ -s /etc/rsyslog.conf ]
	then
        log=`cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep '/^([[:space:]]*authpriv\.\*[[:space:]]*|[[:space:]]*authpriv\.info.*[[:space:]]*|[[:space:]]*\*\.\*[[:space:]]*)'`
		if [[ -n "$log" ]]
		then
			echo yes
		else
			echo no
		fi
	fi	
}

code[28]="if [ -s /etc/syslog.conf ]
        then
                cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | grep '/^(authpriv\.\*[[:space:]]*|authpriv\.info.*[[:space:]]*|\*\.\*)'
        fi

        if [ -s /etc/rsyslog.conf ]
        then
                cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep '/^(authpriv\.\*[[:space:]]*|authpriv\.info.*[[:space:]]*|\*\.\*)'
        fi"

function fun_29 {
	flag=0
	LOGDIR=`if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf| grep -v "^[[:space:]]*#"|awk '{print $2}'|sed 's/^-//g'|grep '^\s*\/';fi`
	for file in $LOGDIR
	do
		file_perm=`ls -l $file | awk '{print $1}'`
		char1=${file_perm:0-1:1}
		if [[ $char1 = "x" ]]
                then
                        num1=1
                else
                        num1=0
                fi
		char2=${file_perm:0-2:1}
		if [[ $char2 = "w" ]]
                then
                        num2=1
                else
                        num2=0
                fi
		char3=${file_perm:0-3:1}
		if [[ $char3 = "r" ]]
                then
                        num3=1
                else
                        num3=0
                fi
		char4=${file_perm:0-4:1}
		if [[ $char4 = "x" ]]
                then
                        num4=1
                else
                        num4=0
                fi
		char5=${file_perm:0-5:1}
		if [[ $char5 = "w" ]]
                then
                        num5=1
                else
                        num5=0
                fi
		char6=${file_perm:0-6:1}
		if [[ $char1 = "r" ]]
                then
                        num6=1
                else
                        num6=0
                fi
		char7=${file_perm:0-7:1}
		if [[ $char7 = "x" ]]
                then
                        num7=1
                else
                        num7=0
                fi
		char8=${file_perm:0-8:1}
		if [[ $char8 = "w" ]]
                then
                        num8=1
                else
                        num8=0
                fi
		char9=${file_perm:0-9:1}
		if [[ $char9 = "r" ]]
                then
                        num9=1
                else
                        num9=0
                fi
		str1=$[($num3 * 4) + ($num2 * 2) + $num1]
		str2=$[($num6 * 4) + ($num5 * 2) + $num4]
		str3=$[($num9 * 4) + ($num8 * 2) + $num7]
		file_num=$[($str3 * 100) + ($str2 * 10) + $str1]
		if [ $file_num -gt 640 ]
		then
			flag=1
		else
			flag=0
		fi
	done

	if [ $flag -eq 1 ]
	then
		echo no
	else
		echo yes
	fi
}

code[29]="search=\`find /var/log -type f\`
ls -l \$search"

function fun_30 {
	if [ -s /etc/syslog.conf ]
	then
        log=`cat /etc/syslog.conf | grep -v "^[[:space:]]*#" | grep '/^[[:space:]]*authpriv\.\*[[:space:]]*'`
		if [[ -n "$log" ]]
		then
			echo yes
		else
			echo no
		fi		
	fi

	if [ -s /etc/rsyslog.conf ]
	then
        log=`cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep '/^(authpriv\.\*[[:space:]]*|authpriv\.info.*[[:space:]]*|\*\.\*)'`
		if [[ -n "$log" ]]
		then
			echo yes
		else
			echo no
		fi
	fi
}

code[30]="if [ -s /etc/syslog.conf ]
        then
                cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | grep '/^(authpriv\.\*[[:space:]]*|authpriv\.info.*[[:space:]]*|\*\.\*)'
        fi

        if [ -s /etc/rsyslog.conf ]
        then
                cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep '/^(authpriv\.\*[[:space:]]*|authpriv\.info.*[[:space:]]*|\*\.\*)'
        fi"

function fun_31 {
	if [ -s /etc/pam.d/su ]
	then
        	line=`cat /etc/pam.d/su | grep '/^[[:space:]]*auth[[:space:]]*(required|requisite)[[:space:]]*pam_wheel\.so[[:space:]]*(use\_uid|group\=wheel)[[:space:]]*'`
        	if test $line
        	then
                su_wheel=yes
                #echo su_wheel=$su_wheel
            else
                su_wheel=no
                #echo su_wheel=$su_wheel
            fi
    else
        su_wheel=no
		#echo su_wheel=$su_wheel
    fi
	echo $su_wheel
	unset line su_wheel
}

code[31]="if [ -s /etc/pam.d/su]
        then
                line=\`cat /etc/pam.d/su | grep '/^[[:space:]]*auth[[:space:]]*(required|requisite)[[:space:]]*pam_wheel\.so[[:space:]]*(use\_uid|group\=wheel)[[:space:]]*'\`
                if test \$line
                then
                        su_wheel=yes
                        echo su_wheel=\$su_wheel
                else
                        su_wheel=no
                        echo su_wheel=\$su_wheel
                fi
        else
                su_wheel=no
                echo su_wheel=\$su_wheel
        fi

	unset line
	unset su_wheel"

function fun_32 {
	oldIFS=$IFS
	IFS=$'\n'
	
	if [ -s /etc/syslog.conf ]
	then
        	for line in $(cat /etc/syslog.conf)
        	do
                	if test "`echo $line | grep -v ^[[:space:]]*# | awk '{print $1}' | gawk '/^[[:space:]]*(cron|\*\.)/{print $0}'`"
                	then
                        	cron=yes
                        	item=`echo $line | awk '{print $1}'`
                        	dir=`echo $line | awk '{print $2}'`
                        	#echo $item=$dir
                	fi
        	done
	else
        	cron=no
	fi
	
	if [ -s /etc/rsyslog.conf ]
	then
        	for line in $(cat /etc/rsyslog.conf)
        	do
                	if test "`echo $line | grep -v ^[[:space:]]*# | awk '{print $1}' | grep '/^[[:space:]]*(cron|\*\.)'`"
                	then
                        	cron=yes
                        	item=`echo $line | awk '{print $1}'`
                        	dir=`echo $line | awk '{print $2}'`
                        	#echo $item=$dir
                	fi
        	done
	else
        	cron=no
	fi

	echo $cron

	IFS=$oldIFS

	unset oldIFS conf cron
}

code[32]="oldIFS=\$IFS
        IFS=$'\\\n'

        if [ -s /etc/syslog.conf ]
        then
                for line in \$(cat /etc/syslog.conf)
                do
                        if test \"\`echo \$line | grep -v ^[[:space:]]*# | awk '{print \$1}' | grep '/^[[:space:]]*(cron|\*\.)'\`\"
                        then
                                cron=set
                                item=\`echo \$line | awk '{print \$1}'\`
                                dir=\`echo \$line | awk '{print \$2}'\`
                                echo \$item=\$dir
                        fi
                done
        else
                cron=unset
        fi

        echo cron=\$cron

        IFS=\$oldIFS

        unset oldIFS
        unset conf
        unset cron"

function fun_33 {
	if [[ -f /var/log/messages ]];then
		mess_chmod=`ls -l /var/log/messages | awk '{print $1}'`
    		six_chmod=`echo ${mess_chmod:5:1}`
    		if [ $six_chmod = a ]
    		then
        		echo yes
    		else
    		#lsattr $search
        		echo no
    		fi
	else
		echo no
	fi
    	unset mess_chmod six_chmod
}

code[33]="mess_chmod=\`ls -l /var/log/messages | awk '{print \$1}'\`
    	six_chmod=`echo \${mess_chmod:5:1}`
    	if [ \$six_chmod = a ]
    	then
        	echo yes
    	else
    	#lsattr \$search
        	echo no
    	fi
    	unset mess_chmod six_chmod"

function fun_34 {
	flag=0
	for f in /proc/sys/net/ipv4/conf/*/accept_source_route
	do
        	result=`cat $f`
        	if [ $result -ne 0 ]
		then
			let 'flag+=1'
		fi
	done
	
	if [ $flag -gt 0 ]
	then
		echo no
	else
		echo yes
	fi
}

code[34]="for f in /proc/sys/net/ipv4/conf/*/accept_source_route
        do
                result=\`cat \$f\`
                echo \$f=\$result
        done"

function fun_35 {
	num1=`cat /etc/host.conf | grep '/^[[:space:]]*order[[:space:]]*hosts\,bind[[:space:]]*'`
	num2=`cat /etc/host.conf | grep '/^[[:space:]]*multi[[:space:]]*on[[:space:]]*'`
	num3=`cat /etc/host.conf | grep '/^[[:space:]]*nospoof[[:space:]]*on[[:space:]]*'`
	
	if [[ -n "$num1" ]]&&[[ -n "$num2" ]]&&[[ -n "$num3" ]]
	then
		echo yes
	else
		echo no
	fi
}

code[35]="cat /etc/host.conf"

function fun_36 {
	sys_attack=`cat /proc/sys/net/ipv4/tcp_syncookies`
	if [ $sys_attack -eq 1 ]
	then
		echo yes
	else
		echo no
	fi
}

code[36]="sys_attack=\`cat /proc/sys/net/ipv4/tcp_syncookies\`
	if [ \$sys_attack -eq 1 ]
	then
		echo yes
	else
		echo no
	fi"

function fun_37 {
	HISTSIZE=`cat /etc/profile | grep HISTSIZE | head -1 | awk -F[=] '{print $2}'`
	#echo HISTSIZE=$HISTSIZE
	if [[ $HISTSIZE -le 5 ]]
	then
		echo yes
	else
		echo no
	fi
}

code[37]="HISTSIZE=\`cat /etc/profile | grep HISTSIZE | head -1 | awk -F[=] '{print \$2}'\`
	echo HISTSIZE=\$HISTSIZE"

function fun_38 {
	source ~/.bashrc
	alia_ls=`alias | grep -E 'ls='`
	alia_rm=`alias | grep -E 'rm='`
	#echo "$alia"
	if [[ -n "$alia_ls" ]] && [[ -n "$alia_rm" ]]
	then
		echo yes
	else
		echo no
	fi
}

code[38]="source ~/.bashrc
	alia_ls=`alias | grep -E 'ls='`
	alia_rm=`alias | grep -E 'rm='`"

function fun_39 {
	if [[ $os_name = "kylin" ]]||[[ $os_name = "linx" ]]
	then
		#echo $os_name
		echo yes
	else
		echo no
	fi
}

code[39]="if [[ \$os_name = \"kylin\" ]]||[[ \$os_name = \"linx\" ]]
        then
                echo \$os_name
        else
                echo no
        fi"

function fun_40 {
	email=`ps -ef | grep E-Mail | grep -v grep`
	web=`ps -ef | grep Web | grep -v grep`
	ftp=`ps -ef | grep FTP | grep -v grep`
	telnet=`ps -ef | grep telnet | grep -v grep`
	rlogin=`ps -ef | grep rlogin | grep -v grep`
	smb=`ps -ef | grep SMB | grep -v grep`
	
	if [[ -n "$email" ]] || [[ -n "$web" ]] || [[ -n "$ftp" ]] || [[ -n "$telnet" ]] || [[ -n "$rlogin" ]] || [[ -n $smb ]]
	then
		echo no
	else
		echo yes
	fi
	unset service email web ftp telnet rlogin
}

code[40]="service=\`chkconfig \-\-list | awk '{print \$1}'\`
        echo \"\$service\"

        unset service"

function fun_41 {
	root_logins=0
	root_logins=`who | awk '{print $1}' | sed -n '/^root$/p' | wc -l`
	#echo root_logins=$root_logins
	if [ $root_logins -eq 0 ]
	then
		echo yes
	else
		echo no
	fi
}

code[41]="root_logins=\`who | awk '{print \$1}' | sed -n '/^root$/p' | wc -l\`
        echo root_logins=\$root_logins"

function fun_42 {
	count=0
	item=`netstat -nultp | grep -E ^'tcp|udp'`

	oldIFS=$IFS
	IFS=$'\n'

	for line in $item
	do
        	proto=`echo "$line"|awk '{print $1}'`
        	address=`echo "$line"|awk '{print $4}'`
        	socket=`echo "$address"|awk -F ':' '{print $2}'`
			count=$(expr $count + 1)
        	#echo $proto.$socket
	done

	if [ $count -gt 15 ]
	then
		echo no
	else
		echo yes
	fi
	IFS=$oldIFS
	unset oldIFS proto address socket count
}

code[42]="item=\`netstat -nultp | grep -E ^'tcp|udp'\`

        oldIFS=\$IFS
        IFS=$'\\\n'

        for line in \$item
        do
                proto=\`echo \"\$line\"|awk '{print \$1}'\`
                address=\`echo \"\$line\"|awk '{print \$4}'\`
                socket=\`echo \"\$address\"|awk -F ':' '{print \$2}'\`

                echo \$proto.\$socket
        done

        IFS=\$oldIFS
        unset oldIFS
        unset proto
        unset address
        unset socket"

#function fun_43 {
#	route_table=NULL
#	route_table=`route -n | tail -n +3`
#	echo "$route_table"
#}

#code[43]="route_table=NULL
#	route_table=\`route -n | tail -n +3\`
#        echo \"\$route_table\""

function fun_43 {
	file="/lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko"
	if [ -e $file ]
	then
		echo no
	else
		echo yes
	fi
}

code[43]="file=\"/lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko\""

function fun_44 {
	if [[ $os_name = "linx" ]]
	then
		string1=`lsmod | grep lsm_linx`
		string2=`lsmod | grep linx_sec`
		if [[ -n $string1 ]] || [[ -n $string2 ]]
		then
			echo yes
		else
			echo no
		fi
	elif [[ $os_name = "kylin" ]]
	then
		rbapol > /dev/null 2>&1 &
		if [[ $? -eq 0 ]]
		then
			echo no
		else
			echo yes
		fi
	else
		echo no
	fi
}

code[44]="if [[ \$os_name = \"linx\" ]]
	then
		lsmod | grep linx
	elif [[ \$os_name = \"kylin\" ]]
	then
		rbapol
		if [[ \$? -eq 0 ]]
		then
			echo yes
		else
			echo no
		fi
	else
		echo no
	fi"

function fun_45 {
	service=`ps aux | grep -w auditd | grep -v grep`
	if test "$service"
	then
        audit=1
        if [ -s /var/log/audit/audit.log ]
        then
            #ls_show=`ls -l /var/log/audit/audit.log`
            #lsattr_show=`lsattr /var/log/audit/audit.log`
			echo yes
		else
			echo no
        fi
	else
        echo no
	fi

	#echo audit=$audit
	#echo ls=$ls_show
	#echo lasttr=$lsattr_show

	unset service audit ls_show lsattr_show
}

code[45]="service=\`ps aux | grep -w auditd | grep -v grep\`
        if test \"$service\"
        then
                audit=set
                if [ -s /var/log/audit/audit.log ]
                then
                        ls_show=\`ls -l /var/log/audit/audit.log\`
                        lsattr_show=\`lsattr /var/log/audit/audit.log\`
                fi
        else
                audit=un_set
        fi

        echo audit=\$audit
        echo ls=\$ls_show
        echo lasttr=\$lsattr_show

        unset service audit ls_show lsattr_show"

function fun_46 {
	file=`find / -name SCADA.p12 -o -name SCADA.cer 2> /dev/null`

	if test "$file"
	then
        	scada=1
			echo yes
	else
        	scada=0
			echo no
	fi

	#echo scada=$scada

	unset file scada
}

code[46]="file=\`find / -name SCADA.p12 -o -name SCADA.cer 2> /dev/null\`

        if test \"\$file\"
        then
                scada=1
        else
                scada=0
        fi

        echo scada=\$scada

        unset file
        unset scada"

function fun_47 {
	file=`find / -name AGC.p12 -o -name SCADA.cer 2> /dev/null`
	if test "$file"
	then
        	AGC=1
			echo yes
	else
        	AGC=0
			echo no
	fi

	#echo AGC=$AGC

	unset file AGC
}

code[47]="file=\`find / -name AGC.p12 -o -name SCADA.cer 2> /dev/null\`
        if test \"\$file\"
        then
                AGC=1
        else
                AGC=0
        fi

        echo AGC=\$AGC

        unset file
        unset AGC"

function fun_48 {
	count=0
    	while read line
    	do
        	uid=`echo $line | awk -F ':' '{print $3}'`
        	if [ $uid -eq 0 ]
        	then
            		((count=$count-1))
        	fi
    	done < /etc/passwd
    	if [ $count -le 1 ]
    	then    
       		echo yes
    	else    
        	echo no
    	fi
}

code[48]="count=0
    	while read line
    	do
        	uid=\`echo \$line | awk -F ':' '{print \$3}'\`
        	if [ \$uid -eq 0 ]
        	then
            		((count=\$count-1))
        	fi
    	done < /etc/passwd
    	if [ \$count -le 1 ]
    	then    
       		echo yes
    	else    
        	echo no
    	fi"

function fun_49 {
	oldIFS=$IFS
        IFS=$'\n'

        for line in $(cat /etc/security/limits.conf)
	do
		if [ `echo $line | grep -v "[[:space:]]*#" | awk '{print $3}' | grep -x "stack"` ]
		then
			stack=`echo $line | awk '{print $4}'`
		elif [ `echo $line | grep -v "[[:space:]]*#" | awk '{print $3}' | grep -x "rss"` ]
		then
			rss=`echo $line | awk '{print $4}'`
		fi
	done
	echo no
	IFS=$oldIFS
	unset oldIFS line
}

code[49]="oldIFS=\$IFS
        IFS=$'\\\n'
	
	line1=Null
	line2=Null
        for line in \$(cat /etc/security/limits.conf)
        do
                if [ \`echo \$line | grep -v \"[[:space:]]*#\" | awk '{print \$3}' | grep -x \"stack\"\` ]
                then
			line1=\$line
                        echo \$line
                elif [ \`echo \$line | grep -v \"[[:space:]]*#\" | awk '{print \$3}' | grep -x \"rss\"\` ]
                then
			line2=\$line
                        echo \$line
                fi
        done
        IFS=\$oldIFS
        unset oldIFS line"

function fun_50 {
	kernel=`uname`
	kernel_version=`uname -v`
	echo yes
}

code[50]="kernel=\`uname\`
	kernel_version=\`uname -v\`"

function fun_51 {
	rss_hard=`cat /etc/security/limits.conf | grep -v "[[:space:]]*#" | grep "[[:space:]]*[[:space:]]*hard[[:space:]]*rss[[:space:]]*[[:digit:]]" | awk '{print $4}'`
	core_soft=`cat /etc/security/limits.conf | grep -v "[[:space:]]*#" | grep "[[:space:]]*[[:space:]]*soft[[:space:]]*core[[:space:]]*[[:digit:]]" | awk '{print $4}'`
	if [[ $rss_hard -eq 0 ]] && [[ $core_soft -eq 0 ]]
	then 
		echo yes
	else
		echo no
	fi
}

code[51]="core dump"

ipaddr=$(echo $1 | awk -F '.' '$1<255 && $1>=0 && $2<255 && $2>=0 && $3<255 && $3>=0 && $4<255 && $4>=0 {print 1}') 

if [ $ipaddr -ne 1 ]
then
    echo Usage:ip address wrong
    exit -1
fi

if [ $# -gt 3 ]
then
        echo Usage:too many args,ignore the fourth !
elif [ $# -lt 3 ]
then
	echo Usage:lack of args!
	exit -1
fi

oldIFS=$IFS
IFS=,
count=0

for (( i=0; i <= 51; i++ ))
do
        arry[$i]=0
done

for arg in $2
do
        if test "`echo $arg | grep -x -E "[0-9]|[1-4][0-9]|5[0-1]"`"
        then
                arry[$arg]=$[${arry[$arg]} + 1]
                if [[ ${arry[$arg]} -gt 1 ]]
                then
                        echo "arg "$arg" repeated emergence,only handle once"
                else
                        count=$[$count + 1]
                fi
        else
                echo "arg "$arg" \"> 51\" or \"< 0\" or \"not a number\",ignore it"
        fi
done

IFS=$oldIFS

unset LANG
os_full_name=`cat /etc/issue | head -1 | awk -F "release" '{print $1}'`
if [[ `echo $os_full_name | grep -i "red hat"` ]]
then
	os_name="rhel"
elif [[ `echo $os_full_name | grep -i "KYLIN"` ]]
then
	os_name="kylin"
elif [[ `echo $os_full_name | grep -i "Ubuntu"` ]]
then
	os_name="Ubuntu"
elif [[ `echo $os_full_name | grep -i "Debian"` ]]
then
	os_name="Debian"
fi

if [[ $os_name = "rhel" ]]
then
	os_version=`cat /etc/issue | head -1 | awk -F "release" '{print $2}'`
elif [[ $os_name = "kylin" ]]
then
	os_version=`cat /etc/issue | head -1 | awk '{print $2}'`
elif [[ $os_name = "Ubuntu" ]]
then
	os_version=`cat /etc/issue | head -1 | awk '{print $2}'`
elif [[ $os_name = "Debian" ]]
then
	os_version=`cat /etc/issue | head -1 | awk '{print $3}'`
fi

date=`date "+%Y-%m-%d %H:%M:%S"`
coding=`echo $LANG`
coding_value="UTF-8"

if test "`echo $coding | grep GB`"
then
	coding_value="GBK"
fi

xmlfile=$3".xml"
#echo $xmlfile

if [ -e /tmp/$xmlfile ]
then
	rm -f /tmp/$xmlfile
#	echo "$xmlfile exists,remove it !"
fi

touch /tmp/$xmlfile

echo "<?xml version='1.0' encoding='$coding_value'?>" > /tmp/$xmlfile
echo "<result>" >> /tmp/$xmlfile
echo "<osName><![CDATA["$os_name"]]></osName>" >> /tmp/$xmlfile
echo "<version><![CDATA["$os_version"]]></version>" >> /tmp/$xmlfile
echo "<ip><![CDATA["$1"]]></ip>" >> /tmp/$xmlfile
echo "<type><![CDATA[/server/"$os_name"]]></type>" >> /tmp/$xmlfile
echo "<startTime><![CDATA["$date"]]></startTime>" >> /tmp/$xmlfile
echo "<pId><![CDATA[$$]]></pId>" >> /tmp/$xmlfile

echo -e "\t<scripts>" >> /tmp/$xmlfile

if [[ ${arry[0]} -gt 0 ]]&&[[ $count -eq 1 ]]
then
	for (( i=1; i <= 51; i++ ))
        do
                        echo -e "\t\t<script>" >> /tmp/$xmlfile
                        echo -e "\t\t\t<id>"$i"</id>" >> /tmp/$xmlfile
                        echo -e "\t\t\t<code><![CDATA[${code[$i]}]]></code>" >> /tmp/$xmlfile
                        #echo "$i"
                        value=$(fun_$i)
                        echo -e "\t\t\t<value><![CDATA[$value]]></value>" >> /tmp/$xmlfile
                        echo -e "\t\t</script>" >> /tmp/$xmlfile
        done
elif [[ ${arry[0]} -gt 0 ]]&&[[ $count -gt 1 ]]
then
        echo arg "0" means test all the items,ignore other args
        for (( i=1; i <= 51; i++ ))
        do
                        echo -e "\t\t<script>" >> /tmp/$xmlfile
                        echo -e "\t\t\t<id>"$i"</id>" >> /tmp/$xmlfile
                        echo -e "\t\t\t<code><![CDATA[${code[$i]}]]></code>" >> /tmp/$xmlfile
                        #echo "$i"
                        value=$(fun_$i)
                        echo -e "\t\t\t<value><![CDATA[$value]]></value>" >> /tmp/$xmlfile
                        echo -e "\t\t</script>" >> /tmp/$xmlfile
        done
else
        for (( i=1; i <= 51; i++ ))
        do
                if [ ${arry[$i]} -gt 0 ]
                then
                        echo -e "\t\t<script>" >> /tmp/$xmlfile
                        echo -e "\t\t\t<id>"$i"</id>" >> /tmp/$xmlfile
                        echo -e "\t\t\t<code><![CDATA[${code[$i]}]]></code>" >> /tmp/$xmlfile
			#echo "$i"
                        value=$(fun_$i)
                        echo -e "\t\t\t<value><![CDATA[$value]]></value>" >> /tmp/$xmlfile
			echo -e "\t\t</script>" >> /tmp/$xmlfile

                fi
        done
fi

echo -e "\t</scripts>" >> /tmp/$xmlfile
enddate=`date "+%Y-%m-%d %H:%M:%S"`
echo "<endTime><![CDATA["$enddate"]]></endTime>" >> /tmp/$xmlfile
echo "</result>" >> /tmp/$xmlfile
#echo -e "write  result to xml file\nexecute end!\n"
