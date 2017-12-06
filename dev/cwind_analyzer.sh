#!/bin/sh

PYTHON_BIN=/usr/bin/python
PCAP_ANALYZER=/Users/miles/Desktop/speedup_project/cwnd_analyzer/lib/pcap2har-master/main.py
CWIND_COUNT_ANALYZER=/Users/miles/Desktop/speedup_project/cwnd_analyzer/dev/cwind_analyzer.py
PCAP_FILE=$1
TARGET_IP=$2
OUTPUT_FILE=/Users/miles/Desktop/speedup_project/cwnd_analyzer/tmp/tmp.timestamp
LOG_FILE=/Users/miles/Desktop/speedup_project/cwnd_analyzer/log/pcap2har.log
NUM=$3
TARGET_PATH=$4
HOST=$5
ETH=$6
CURL_BIN=/usr/bin/curl
OUTPUT_DIR=/Users/miles/Desktop/speedup_project/cwnd_analyzer/tmp/

#sh cwind_analyzer.sh /home/uaq/opbin/xuye/local/cwnd_analyzer/data/test.pcap 115.231.103.136 100 http://115.231.103.136/static.mmtrix.com/v3.0/g1/M00/F8/F5/CgpkElVca5SAMuq9AADvCCKvwAM719.png cdn.mmtrix.com em1
if [ "" = "${PCAP_FILE}" -o "" = "${TARGET_IP}" -o "" = "${NUM}" -o "" = "${TARGET_PATH}" -o "" = "${HOST}" ];then
    echo "invalid parameters"
    exit 1
fi

if [ "" = "${ETH}" ];then
    ETH=em2
fi

TCPDUMP_PID=`ps aux|grep tcpdump|grep pcap|awk '{print $2}'`
if [ "" != "${TCPDUMP_PID}" ];then
    kill -9 ${TCPDUMP_PID} 
fi

#echo "start to capture tcp packages"
nohup /usr/sbin/tcpdump -i ${ETH} -w ${PCAP_FILE} host ${TARGET_IP} > /dev/null 2>&1 &

#echo "start to curl http://${TARGET_IP}/${TARGET_PATH} with host:${HOST}"
b='#'
for i in `seq ${NUM}`;do printf "progress:[%-100s]%d%%\r" $b $i; b=#$b; ${CURL_BIN} -H "Host: ${HOST}" "http://${TARGET_IP}/${TARGET_PATH}" > /dev/null 2>&1 && sleep 1;done
#for i in `seq ${NUM}`;do  ${CURL_BIN} -H "Host: ${HOST}" "http://${TARGET_IP}/${TARGET_PATH}" > /dev/null 2>&1 && sleep 1;done

TCPDUMP_PID=$(ps aux|grep tcpdump|grep pcap|awk '{print $2}')
#echo "start to kill tcpdump process pid:"${TCPDUMP_PID}
kill -9 ${TCPDUMP_PID} > /dev/null 2>&1 

sleep 1
#echo "start to analyise pcap"
${PYTHON_BIN} ${PCAP_ANALYZER} ${PCAP_FILE} --log=${LOG_FILE}| grep "pkt_src_ip" > ${OUTPUT_FILE} && chown miles:staff ${OUTPUT_FILE} && chown miles:staff ${PCAP_FILE} && ${PYTHON_BIN} ${CWIND_COUNT_ANALYZER} ${OUTPUT_FILE} ${TARGET_IP} 

if [ 0 != $? ];then
    echo "${TARGET_IP} something wrong"
fi
