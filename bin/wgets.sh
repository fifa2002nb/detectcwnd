#!/bin/sh

NUM=$1
TARGET_URL=$2
HOST=$3
WGET_BIN=/usr/bin/wget
CURL_BIN=/usr/bin/curl
OUTPUT_DIR=/home/uaq/opbin/xuye/local/cwnd_analyzer/tmp

if [ "" = ${NUM} -o "" = ${TARGET_URL} ];then
    echo "invalid parameters"
    exit 1
fi

#for i in `seq ${NUM}`;do echo $i;cd ${OUTPUT_DIR} && ${WGET_BIN} ${TARGET_URL} > /dev/null 2>&1 && sleep 1;done && rm -rf ${OUTPUT_DIR}/*
for i in `seq ${NUM}`;do echo $i;cd ${OUTPUT_DIR} && ${CURL_BIN} -H "Host: ${HOST}" ${TARGET_URL} > /dev/null 2>&1 && sleep 1;done && rm -rf ${OUTPUT_DIR}/*
