#!/bin/sh

SOURCE_IP_FILE=/home/uaq/opbin/xuye/local/cwnd_analyzer/data/cdn_ip_list
CWND_ANALYZER=/home/uaq/opbin/xuye/local/cwnd_analyzer/dev/cwind_analyzer.sh
PCAP_FILE=$1
NUM=$2
TARGET_PATH=$3
HOST=$4
TARGET_CNET_IP_LIST=`cat ${SOURCE_IP_FILE} | grep cnet | awk '{print $2}'`
TARGET_CNC_IP_LIST=`cat ${SOURCE_IP_FILE} | grep cnc | awk '{print $2}'`

if [ "" = "${PCAP_FILE}" -o "" = "${NUM}" -o "" = "${TARGET_PATH}" -o "" = "${HOST}" ];then
    echo "invalid parameters"
fi

for i in `echo ${TARGET_CNET_IP_LIST}`;do /bin/sh ${CWND_ANALYZER} ${PCAP_FILE} $i ${NUM} ${TARGET_PATH} ${HOST} em1;done
for i in `echo ${TARGET_CNC_IP_LIST}`;do /bin/sh ${CWND_ANALYZER} ${PCAP_FILE} $i ${NUM} ${TARGET_PATH} ${HOST} em2;done
