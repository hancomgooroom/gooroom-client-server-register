#!/bin/bash

#
# Automatic GPMS registration script 
#  written by Gooroom Project Team <shjung@gooroom.kr>
#

if [ $ENABLE_AUTO_REGI != 'Yes' ] 
then
        exit 0
fi

if [ -z $CLIENT_NAME ]
then
	CMD="gooroom-client-server-register noninteractive-regkey -d $GKM_SERVER -u "AUTO_REGED" -k $REG_KEY -r 2"
else
	CMD="gooroom-client-server-register noninteractive-regkey -d $GKM_SERVER -m $CLIENT_NAME -u "AUTO_REGED" -k $REG_KEY -r 2"
fi

if [ -z $GKM_SERVER ] || [ -z $REG_KEY ]
then
        echo Configuration is not properly set
	echo $GKM_SERVER >> /tmp/gpms_autoregi_debug.txt
	echo $REG_KEY >> /tmp/gpms_autoregi_debug.txt
	echo $CLIENT_NAME >> /tmp/gpms_autoregi_debug.txt
        exit 1
fi

systemctl enable gooroom-agent
systemctl start gooroom-agent
sleep 1
if ( dbus-send --system --print-reply --type=method_call --dest='kr.gooroom.agent' '/kr/gooroom/agent' kr.gooroom.agent.do_task string:'{"module" : {"module_name" : "SERVER","task" : {"task_name" : "grm_heartbit","in" : {}}}}' | grep "\"status\"\:\ \"200\"" )
#if ( ! true  ) 
then
	rm -f /etc/gooroom/gooroom-client-server-register/gcsr_auto.conf
	echo gpms-server is already connected.
else
	systemctl stop gooroom-agent
	DO="yes"
	while [ "$DO" == "yes"  ]
	do
		
		if ( $CMD )
		then
			DO="no"	
			rm -f /etc/gooroom/gooroom-client-server-register/gcsr_auto.conf
		fi
	    sleep 2
	done
	systemctl enable gooroom-agent
	systemctl start gooroom-agent
fi
