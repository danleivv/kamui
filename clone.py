#!/usr/bin/env python

import dpkt
import sys
import colored
import datetime


def adjoint(pre, data):
    if not pre:
        return True
    if len(pre.data) == 0 and pre.ack == data.ack and pre.seq == data.seq:
        return True
    if data.seq == pre.ack and data.ack == pre.seq + len(pre.data):
        return True
    return False


def calc_offset(tcp, base, bt):
    mode = '\x7f\x00\x00' if bt == 6 else '\7f'
    rep = ''
    offset = []
    while tcp.rfind(mode) != -1:
        pos = tcp.rfind(mode)
        tcp, addr, tail = tcp[:pos-bt+1], tcp[pos-bt+1:pos+1], tcp[pos+1:]
        addr = int(addr[::-1].encode('hex'), 16) - int(base, 16)
        rep = '#%x#' % addr + tail + rep
        offset.append(hex(addr))
    return tcp + rep, offset


if __name__ == '__main__':
    pcap = dpkt.pcap.Reader(open(sys.argv[1]))
    pkt = {}

    for _, buf in pcap:
        ipdata = dpkt.ethernet.Ethernet(buf).data
        tcpdata = ipdata.data
        dport, sport = tcpdata.dport, tcpdata.sport
        if dport > sport:
            dport, sport = sport, dport
        if (dport, sport) not in pkt:
            pkt[(dport, sport)] = [tcpdata]
        else:
            pkt[(dport, sport)].append(tcpdata)

    for port in pkt:
        if port[1] != 51132:
            continue
        tcpstream = pkt[port]
        pre = None
        client = []
        server = []
        offsets = []
        log = []
        base = None
        basepos = None
        x64 = []
        x32 = []
        for data in tcpstream:
            if adjoint(pre, data) and len(data.data):
                if data.dport < data.sport:
                    client.append(data.data)
                    log.append(len(client))
                    if basepos != None:
                        if '\x7f\x00\x00' in data.data:
                            x64.append(len(client) - 1)
                        elif '\x7f' in data.data:
                            x32.append(len(client) - 1)
                else:
                    server.append(data.data)
                    if '\x7f' in data.data:
                        basepos = len(server) - 1
                    log.append(-len(server))
            pre = data

        if x64:
            pos = server[basepos].rfind('\x7f')
            base = server[basepos][pos-5:pos+1][::-1].encode('hex')
            server[basepos] = server[basepos][:pos-5] + '{{base}}' + server[basepos][pos+1:]
            for item in x64:
                client[item], offset = calc_offset(client[item], base, 6)
                offsets += offset
        elif x32:
            pos = server[basepos].rfind('\x7f')
            base = server[basepos][pos-3:pos+1][::-1].encode('hex')
            server[basepos] = server[basepos][:pos-3] + '{{base}}' + server[basepos][pos+1:]
            for item in x32:
                client[item], offset = calc_offset(client[item], base, 4)
                offsets += offset

        if x64 or x32:
            filename = '%s->%s.%s.log' % (port[0], port[1], datetime.datetime.now().strftime('%H%M%S'))
            with open(filename, 'w') as fw:
                if x64:
                    fw.write('x64\n')
                else:
                    fw.write('x32\n')
                fw.write(' '.join(offsets) + '\n')
                for idx in log:
                    if idx < 0:
                        idx = -1 - idx
                        if '{{base}}' in server[idx]:
                            fw.write('--------\n')
                            fw.write(server[idx])
                            fw.write('--------\n')
                    else:
                        idx -= 1
                        fw.write(client[idx])
