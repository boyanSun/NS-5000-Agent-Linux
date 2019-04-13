#!/bin/bash

dir=`dirname "$0"`
cd $dir
cur_dir=`pwd`

license_dir="$cur_dir"/license

if [ ! -f get-machine-id ];then
    echo "Can not find get-machine-id program."
    exit 1
fi

machine_id=`./get-machine-id`

lic=`ls "$license_dir" | grep "$machine_id"`
if [ "$lic" != "" ];then
echo $lic
cp "$license_dir"/"$lic" /etc/agent.lic
fi

exit 0
