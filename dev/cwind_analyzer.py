#!/bin/python
# -*- coding: utf8 -*-

import sys

def parseAccessLog(log_file, target_ip):
    '''
    pkt_src_ip:211.151.109.110 |172.17.246.160 211.151.109.110 1386052093.110321|211.151.109.110 211.151.109.110 1386052093.276228|172.17.246.160 211.151.109.110 1386052093.276577
    pkt_src_ip:172.17.246.160 pkt_dst_ip:211.151.109.110 pkt_timestamp:1386052109.679427
    ...
    '''
    handshake_list = []
    data_list = []
    with open(log_file, 'r') as f:
        for line in f:
            splits = line.split(' ')
            if 0 >= len(splits):
                print "0 >= len(splits)"
                continue
            pkt_src_ip_str = splits[0]
            pkt_src_ip_splits = pkt_src_ip_str.split(':')
            if 2 != len(pkt_src_ip_splits):
                print "2 != len(pkt_src_ip_splits)"
                continue
            pkt_src_ip = pkt_src_ip_splits[1]
            pkt_src_ip = pkt_src_ip.strip()
            if pkt_src_ip != target_ip:
                continue
            handshake_splits = line.split('|')
            if 4 == len(handshake_splits):
                syn = handshake_splits[1]
                synack = handshake_splits[2]
                ack = handshake_splits[3]
                syn_splits = syn.split(' ')
                if 3 != len(syn_splits):
                    print "3 != len(syn_splits)"
                    continue
                synack_splits = synack.split(' ') 
                if 3 != len(synack_splits):
                    print "3 != len(synack_splits)"
                    continue
                ack_splits = ack.split(' ') 
                if 3 != len(ack_splits):
                    print "3 != len(ack_splits)"
                    continue
                syn_timestamp = syn_splits[2]
                synack_timestamp = synack_splits[2]
                ack_timestamp = ack_splits[2]
                handshake = {}
                handshake['syn_timestamp'], handshake['synack_timestamp'], handshake['ack_timestamp'] = float(syn_timestamp), float(synack_timestamp), float(ack_timestamp)
                handshake_list.append(handshake)
            else:
                if 5 != len(splits):
                    print "5 != len(splits)"
                    continue
                pkt_timestamp = splits[2]
                pkt_flags = splits[3]
                pkt_payload_size = splits[4] 
                pkt_flags = pkt_flags.strip()
                pkt_flags_splits = pkt_flags.split(',')
                data = {"fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0, "ece": 0, "cwr": 0}
                data['pkt_timestamp'], data['pkt_flags'], data['payload_size'] = float(pkt_timestamp), pkt_flags, int(pkt_payload_size)
                for flag in pkt_flags_splits:
                    data[flag] = 1
                data_list.append(data)
    return (handshake_list, data_list)

def calculateCwndCount(handshake_list, data_list):
    sum = 0
    times = 0
    avg_count = 0
    min_count = 10000
    max_count = 0
    count_list = []
    mid_count = 0
    for handshake in handshake_list:
        syn_time = handshake['syn_timestamp']
        synack_time = handshake['synack_timestamp']
        ack_time = handshake['ack_timestamp']
        rtt = synack_time - syn_time
        pdu_start_time = 100000000000000000000
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time > ack_time and data_time < pdu_start_time and 0 < payload_size and 1 == ack:
                pdu_start_time = data_time
                #print pdu_start_time
        if 100000000000000000000 == pdu_start_time:
            continue
        pdu_end_time = pdu_start_time + rtt
        #print "ack_time:%f synack_time:%f rtt:%f pdu_start_time:%f pdu_end_time:%f" % (ack_time, synack_time, rtt, pdu_start_time, pdu_end_time)
        count = 0
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time >= pdu_start_time and data_time <= pdu_end_time and 0 < payload_size and 1 == ack:
                #print "times:%d %f < %f < %f" % (times, pdu_start_time, data_time, pdu_end_time)
                count = count + 1
        if 0 < count:
            if count < min_count:
                min_count = count
            if count > max_count:
                max_count = count
            times = times + 1
            sum += count
            count_list.append(count)
    if 0 != times:
        avg_count = float(sum) / float(times)
        count_list.sort()
        mid_count = count_list[times/2]
    ret = "times:%d max:%d min:%d avg:%.2f mid:%.2f" % (times, max_count, min_count, avg_count, mid_count)
    return ret

def calculateCwndCount_V2(handshake_list, data_list):
    sum = 0
    times = 0
    avg_count = 0
    min_count = 10000
    max_count = 0
    rtt_sum = 0
    rtt_avg = 0.000
    rtt_count = 0
    for handshake in handshake_list:
        syn_time = handshake['syn_timestamp']
        synack_time = handshake['synack_timestamp']
        ack_time = handshake['ack_timestamp']
        rtt2 = synack_time - syn_time
        rtt_count = rtt_count + 1
        rtt_sum = rtt_sum + rtt2
    if 0 < rtt_count:
        rtt_avg = float(rtt_sum) / float(rtt_count)
    for handshake in handshake_list:
        ack_time = handshake['ack_timestamp']
        pdu_start_time = 100000000000000000000
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time > ack_time and data_time < pdu_start_time and 1400 < payload_size and 1 == ack:
                pdu_start_time = data_time
                #print pdu_start_time
        if 100000000000000000000 == pdu_start_time:
            continue
        pdu_end_time = pdu_start_time + rtt_avg
        #print "ack_time:%f synack_time:%f rtt:%f pdu_start_time:%f pdu_end_time:%f" % (ack_time, synack_time, rtt, pdu_start_time, pdu_end_time)
        count = 0
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time >= pdu_start_time and data_time <= pdu_end_time and 1400 < payload_size and 1 == ack:
                #print "times:%d %f < %f < %f" % (times, pdu_start_time, data_time, pdu_end_time)
                count = count + 1
        if 0 < count:
            if count < min_count:
                min_count = count
            if count > max_count:
                max_count = count
            times = times + 1
            sum += count
    if 0 != times:
        avg_count = float(sum) / float(times)
    ret = "times:%d max:%d min:%d avg:%.2f" % (times, max_count, min_count, avg_count)
    return ret

def calculateCwndCount_V3(handshake_list, data_list):
    sum = 0
    times = 0
    avg_count = 0
    min_count = 10000
    max_count = 0
    rtt_sum = 0
    rtt_avg = 0.000
    rtt_mid = 0.000
    rtt_count = 0
    rtt_list = []
    for handshake in handshake_list:
        syn_time = handshake['syn_timestamp']
        synack_time = handshake['synack_timestamp']
        ack_time = handshake['ack_timestamp']
        rtt = synack_time - syn_time
        rtt_list.append(rtt)
        rtt_count = rtt_count + 1
        rtt_sum = rtt_sum + rtt
    if 0 < rtt_count:
        rtt_avg = float(rtt_sum) / float(rtt_count)
        rtt_list.sort()
        rtt_mid = rtt_list[rtt_count/2]
        print "rtt_avg:%f rtt_mid:%f" % (rtt_avg, rtt_mid)
    for handshake in handshake_list:
        ack_time = handshake['ack_timestamp']
        pdu_start_time = 100000000000000000000
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time > ack_time and data_time < pdu_start_time and 1400 < payload_size and 1 == ack:
                pdu_start_time = data_time
                #print pdu_start_time
        if 100000000000000000000 == pdu_start_time:
            continue
        pdu_end_time = pdu_start_time + rtt_mid
        #print "ack_time:%f synack_time:%f rtt:%f pdu_start_time:%f pdu_end_time:%f" % (ack_time, synack_time, rtt, pdu_start_time, pdu_end_time)
        count = 0
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time >= pdu_start_time and data_time <= pdu_end_time and 1400 < payload_size and 1 == ack:
                #print "times:%d %f < %f < %f" % (times, pdu_start_time, data_time, pdu_end_time)
                count = count + 1
        if 0 < count:
            if count < min_count:
                min_count = count
            if count > max_count:
                max_count = count
            times = times + 1
            sum += count
    if 0 != times:
        avg_count = float(sum) / float(times)
    ret = "times:%d max:%d min:%d avg:%.2f" % (times, max_count, min_count, avg_count)
    return ret

def calculateCwndCount_V4(handshake_list, data_list):
    sum = 0
    times = 0
    avg_count1 = 0
    avg_count2 = 0
    min_count1 = 10000
    min_count2 = 10000
    max_count1 = 0
    max_count2 = 0
    rtt_sum = 0
    rtt_avg = 0.000
    rtt_mid = 0.000
    rtt_count = 0
    rtt_list = []
    for handshake in handshake_list:
        syn_time = handshake['syn_timestamp']
        synack_time = handshake['synack_timestamp']
        ack_time = handshake['ack_timestamp']
        rtt = synack_time - syn_time
        rtt_list.append(rtt)
        rtt_count = rtt_count + 1
        rtt_sum = rtt_sum + rtt
    if 0 < rtt_count:
        rtt_avg = float(rtt_sum) / float(rtt_count)
        rtt_list.sort()
        rtt_mid = rtt_list[rtt_count/2]
        print "rtt_avg:%f rtt_mid:%f" % (rtt_avg, rtt_mid)
    for handshake in handshake_list:
        ack_time = handshake['ack_timestamp']
        pdu_start_time = 100000000000000000000
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time > ack_time and data_time < pdu_start_time and 1400 < payload_size and 1 == ack:
                pdu_start_time = data_time
                #print pdu_start_time
        if 100000000000000000000 == pdu_start_time:
            continue
        pdu_end_time = pdu_start_time + rtt_avg
        #print "ack_time:%f synack_time:%f rtt:%f pdu_start_time:%f pdu_end_time:%f" % (ack_time, synack_time, rtt, pdu_start_time, pdu_end_time)
        count = 0
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time >= pdu_start_time and data_time <= pdu_end_time and 1400 < payload_size and 1 == ack:
                #print "times:%d %f < %f < %f" % (times, pdu_start_time, data_time, pdu_end_time)
                count = count + 1
        if 0 < count:
            if count < min_count1:
                min_count1 = count
            if count > max_count1:
                max_count1 = count
            times = times + 1
            sum += count
    if 0 != times:
        avg_count1 = float(sum) / float(times)
    #=================================================================================
    sum = 0
    times = 0
    for handshake in handshake_list:
        ack_time = handshake['ack_timestamp']
        pdu_start_time = 100000000000000000000
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time > ack_time and data_time < pdu_start_time and 1400 < payload_size and 1 == ack:
                pdu_start_time = data_time
                #print pdu_start_time
        if 100000000000000000000 == pdu_start_time:
            continue
        pdu_end_time = pdu_start_time + rtt_mid
        #print "ack_time:%f synack_time:%f rtt:%f pdu_start_time:%f pdu_end_time:%f" % (ack_time, synack_time, rtt, pdu_start_time, pdu_end_time)
        count = 0
        for data in data_list:
            data_time = data['pkt_timestamp']
            psh = data['psh']
            ack = data['ack']
            payload_size = data['payload_size']
            if data_time >= pdu_start_time and data_time <= pdu_end_time and 1400 < payload_size and 1 == ack:
                #print "times:%d %f < %f < %f" % (times, pdu_start_time, data_time, pdu_end_time)
                count = count + 1
        if 0 < count:
            if count < min_count2:
                min_count2 = count
            if count > max_count2:
                max_count2 = count
            times = times + 1
            sum += count
    if 0 != times:
        avg_count2 = float(sum) / float(times)

    ret = "times:%d avg_max:%d avg_min:%d avg_avg:%.2f | mid_max:%d mid_min:%d mid_avg:%.2f" % (times, max_count1, min_count1, avg_count1, max_count2, min_count2, avg_count2)
    return ret

if __name__ == '__main__':
    if len(sys.argv) == 3:
        file_path = sys.argv[1]
        target_ip = sys.argv[2]
        handshake_list, data_list = parseAccessLog(file_path, target_ip)
        ret = calculateCwndCount(handshake_list, data_list)
        print "%s %s" % (target_ip, ret)

