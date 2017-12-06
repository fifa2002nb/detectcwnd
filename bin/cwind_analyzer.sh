#!/bin/sh

PYTHON_BIN=/usr/bin/python
PCAP_ANALYZER=/home/uaq/opbin/xuye/local/cwnd_analyzer/lib/pcap2har-master/main.py
CWIND_COUNT_ANALYZER=/home/uaq/opbin/xuye/local/cwnd_analyzer/bin/cwind_analyzer.py
PCAP_FILE=$1
TARGER_IP=$2
OUTPUT_FILE=/home/uaq/opbin/xuye/local/cwnd_analyzer/tmp/tmp.timestamp
LOG_FILE=/home/uaq/opbin/xuye/local/cwnd_analyzer/log/pcap2har.log

if [ "" = "${PCAP_FILE}" -o "" = "${TARGER_IP}" ];then
    echo "invalid parameters"
    exit 1
fi

#sh cwind_analyzer.sh ../data/5bde2082020b63fe2625903ff6760a42_1_0.pcap 211.151.109.110
${PYTHON_BIN} ${PCAP_ANALYZER} ${PCAP_FILE} --log=${LOG_FILE}| grep "pkt_src_ip" > ${OUTPUT_FILE} && ${PYTHON_BIN} ${CWIND_COUNT_ANALYZER} ${OUTPUT_FILE} ${TARGER_IP} 

if [ 0 != $? ];then
    echo "something wrong"
fi
