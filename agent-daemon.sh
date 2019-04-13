#!/bin/sh
PROC_NAME='sagent-3000-ns'
stopFlag=1

daemonnum=`ps -ef | grep agent-daemon | grep -v $$ | grep -v grep | wc -l`
if [ "$daemonnum" != "0" ];then
    echo "$0 is on running!"
    exit
fi

while true; do
        processnum=`ps -ef |grep $PROC_NAME |grep -v grep |grep -v $0 |wc -l`
        if [ "$processnum" != "2"  ]; then
            PIDS=`ps -ef |grep  $PROC_NAME | grep -v grep |grep -v $0 | awk '{print $2}'`
            for pid in $PIDS
            do
                kill -9 $pid
            done
            if [ $stopFlag -eq 0  ];then
                current=`date +"%F %T,%3N"`
                echo "[ WARNING] [$current] [agent-daemon.sh] [pid:$$] [find $PROC_NAME stoped.] [Success]" >> /usr/local/$PROC_NAME/agentlog_warn.log
                stopFlag=1
            fi
            sleep 1
            processnum=`ps -ef |grep $PROC_NAME |grep -v grep |grep -v $0 |wc -l`
            if [ "$processnum" = "0"  ]; then
                rm -rf /tmp/_MEI*
                cd /usr/local/$PROC_NAME
                ./$PROC_NAME & >/dev/null 2>&1
            fi
            sleep 1
            
            processnum=`ps -ef |grep $PROC_NAME |grep -v grep |grep -v $0 |wc -l`
            if [ "$processnum" = "2"  ]; then
                current=`date +"%F %T,%3N"`
                echo "[ WARNING] [$current] [agent-daemon.sh] [pid:$$] [start $PROC_NAME.] [Success]" >> /usr/local/$PROC_NAME/agentlog_warn.log
                stopFlag=0
            fi
        fi
        sleep 5
done

