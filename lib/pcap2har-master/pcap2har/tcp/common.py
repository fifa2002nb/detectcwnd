import dpkt


def detect_handshake(packets):
    '''
    Checks whether the passed list of tcp.Packet's represents a valid TCP
    handshake. Returns True or False.
    '''
    #from dpkt.tcp import * # get TH_* constants
    if len(packets) < 3:
        return False
    if len(packets) > 3:
        log.error('too many packets for detect_handshake')
        return False
    syn, synack, ack = packets
    fwd_seq = None
    rev_seq = None
    if syn.tcp.flags & dpkt.tcp.TH_SYN and not syn.tcp.flags & dpkt.tcp.TH_ACK:
        # have syn
        fwd_seq = syn.seq  # start_seq is the seq field of the segment
        if (synack.flags & dpkt.tcp.TH_SYN and
            synack.flags & dpkt.tcp.TH_ACK and
            synack.ack == fwd_seq + 1):
            # have synack
            syn_src_ip = '%d.%d.%d.%d' % tuple(map(ord,list(syn.ip.src)))
            synack_src_ip = '%d.%d.%d.%d' % tuple(map(ord,list(synack.ip.src)))
            ack_src_ip = '%d.%d.%d.%d' % tuple(map(ord,list(ack.ip.src)))
            syn_dst_ip = '%d.%d.%d.%d' % tuple(map(ord,list(syn.ip.dst)))
            synack_dst_ip = '%d.%d.%d.%d' % tuple(map(ord,list(syn.ip.dst)))
            ack_dst_ip = '%d.%d.%d.%d' % tuple(map(ord,list(syn.ip.dst)))
            print "pkt_src_ip:%s |%s %s %f|%s %s %f|%s %s %f" % (synack_src_ip, syn_src_ip, syn_dst_ip, syn.ts, synack_src_ip, synack_dst_ip, synack.ts, ack_src_ip, ack_dst_ip, ack.ts)
            rev_seq = synack.seq
            if (ack.flags & dpkt.tcp.TH_ACK and
                ack.ack == rev_seq + 1 and
                ack.seq == fwd_seq + 1):
                # have ack
                return True
    return False
