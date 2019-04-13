#NS-5000-AGENT
if (  $?SSH_CONNECTION == 1 ) then   
    set CLIENT_IP=`echo $SSH_CONNECTION | awk '{print $1}'`
    set CLIENT_PORT=`echo $SSH_CONNECTION | awk '{print $2}'`
    set LOCAL_IP=`echo $SSH_CONNECTION | awk '{print $3}'`    
else
    set CLIENT_IP=""
endif
setenv HISTTIMEFORMAT "%F %T `whoami` "
unset HISTCONTROL

# pts3
#FILENAME=`who am i|awk '{print $2}' | awk -F "/" '{print $1$2}'`
#FILENAME=`tty|awk -F "/" '{print $3$4}'`
#echo "FILENAME = ${FILENAME}"
# pts/3
#TTYNAME=`who am i|awk '{print $2}'`
#echo "TTYNAME = ${TTYNAME}"
# pts3
set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
#echo "PTSNAME = ${PTSNAME}"

set RECORDDIR="/tmp/.record"
set LOCALDIR="/tmp/.record/local"
set SSHDIR="/tmp/.record/ssh"
set X11DIR="/tmp/.record/x11"

if (! -d $RECORDDIR) then
    mkdir -p $RECORDDIR
    chmod 777 $RECORDDIR
    chmod a+t $RECORDDIR
endif

set shlvlnum=2
#get SHLVL value
set shlvlfile="/usr/local/sagent-3000-ns/ShlvlNumber"
if ( -f $shlvlfile ) then
    set shlvlnum=`cat $shlvlfile | awk -F "=" '{print $2}'`
endif

set DT=`date +"%s_%N"`
set X11_SESSION=0
if (  $?DISPLAY == 1 ) then 
    set DISPLAY_NAME=`echo $DISPLAY`
else
    set DISPLAY_NAME=""
endif
#if (  $?XDG_SESSION_COOKIE == 1 ) then 
    #set XDG_NAME=`echo $XDG_SESSION_COOKIE`
#else
    #set XDG_NAME=""
#endif
#if ( "$XDG_NAME" != "" ) then  
set fstr=`echo $DISPLAY_NAME| cut -d \: -f 1`
if ( "$fstr" != "" ) then
    set X11_SESSION=1    
endif
#endif

# ssh login
if ( "$CLIENT_IP" != "" && "$PTSNAME" != "" ) then
    #if ( "$PTSNAME" == ""  ) then
      #exit
    #endif

    if ( ! -d $SSHDIR ) then
        mkdir -p  $SSHDIR
        chmod 777 $SSHDIR
        chmod a+t $SSHDIR
    endif
    if ( $SHLVL ==  1 ) then
        set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
        set LOCAL_IP=`echo $SSH_CONNECTION | awk '{print $3}'`
        setenv LOGFILE "$SSHDIR/$CLIENT_IP-$CLIENT_PORT-${LOGNAME}-${DT}-${PTSNAME}-${LOCAL_IP}-cmd.log"
        touch $LOGFILE
        chmod 777 $LOGFILE
        chmod a+t $LOGFILE
    endif
    if ( $SHLVL == 1 ) then
        set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
        set LOCAL_IP=`echo $SSH_CONNECTION | awk '{print $3}'`
        setenv ECHOFILE "$SSHDIR/$CLIENT_IP-$CLIENT_PORT-${LOGNAME}-${DT}-${PTSNAME}-${LOCAL_IP}-echo.log"
        if ( $?PTSNAME != 0 && "$PTSNAME" != "" ) then
            script -a -f -q $ECHOFILE
        endif

    endif

    #when script logout, ssh logout
    if ( $SHLVL == 1 )  then
        exit
    endif

else if ( "$CLIENT_IP" == "" && $X11_SESSION == 1  )  then
  if ( ! -d $X11DIR )  then
        mkdir -p  $X11DIR
        chmod 777 $X11DIR
        chmod a+t $X11DIR
    endif

    if  ( $SHLVL == $shlvlnum && "$DISPLAY_NAME" != "" )  then
        set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
        set SESSION_PID=`echo $SESSION_MANAGER |awk -F '/' '{print $NF}'`
        setenv LOGFILE "$X11DIR/${LOGNAME}-${DT}-${PTSNAME}-${SESSION_PID}-cmd.log"
        touch $LOGFILE
        chmod 777 $LOGFILE
        chmod a+t $LOGFILE
    endif

    if  ( $SHLVL == $shlvlnum && "$DISPLAY_NAME" != "" )  then
        set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
        set SESSION_PID=`echo $SESSION_MANAGER |awk -F '/' '{print $NF}'`
        setenv ECHOFILE "$X11DIR/${LOGNAME}-${DT}-${PTSNAME}-${SESSION_PID}-echo.log"

        if ( $?PTSNAME != 0 && "$PTSNAME" != "" ) then
            script -a -f -q $ECHOFILE
        endif

    endif

    #when script logout, close the window
    if  ( $SHLVL == $shlvlnum && "$DISPLAY_NAME" != "" )  then
        exit
    endif

# local login
else if ( "$CLIENT_IP" == "" && "$X11_SESSION" == 0 ) then
    if ( ! -d $LOCALDIR ) then
        mkdir -p  $LOCALDIR
        chmod 777 $LOCALDIR
        chmod a+t $LOCALDIR
    endif
    
    if  (( $SHLVL == 1 && "$DISPLAY_NAME" == "" ) || ( $SHLVL == $shlvlnum && "$DISPLAY_NAME" != "" )) then
        if ( $?LOGFILE == 0 ) then
            set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
            if ( "$DISPLAY_NAME" == "" ) then
               set LOCALTYPE='text'
            else
               set LOCALTYPE='gdm'
            endif
            setenv LOGFILE "$LOCALDIR/${LOGNAME}-${DT}-${PTSNAME}-${LOCALTYPE}-cmd.log"
            touch $LOGFILE
            chmod 777 $LOGFILE
            chmod a+t $LOGFILE
        endif
    endif

    if (( $SHLVL == 1 && "$DISPLAY_NAME" == "" ) || ( $SHLVL == $shlvlnum && "$DISPLAY_NAME" != ""  )) then
        if ( $?ECHOFILE == 0 ) then
            set PTSNAME=`tty|awk -F "/" '{print $3$4}'`
            if ( "$DISPLAY_NAME" == "" ) then
               set LOCALTYPE='text'
            else
               set LOCALTYPE='gdm'
            endif
            setenv ECHOFILE "$LOCALDIR/${LOGNAME}-${DT}-${PTSNAME}-${LOCALTYPE}-echo.log"

            if ( $?PTSNAME != 0 && "$PTSNAME" != "" ) then
                script -a -f -q $ECHOFILE
            endif

        endif
    endif

    #when script logout, close the window
    if (( $SHLVL == 1 && "$DISPLAY_NAME" == "" ) || ( $SHLVL == $shlvlnum && "$DISPLAY_NAME" != ""  )) then
        exit
    endif
endif
