#!/usr/bin/env python

import struct
import zlib
import time
import datetime

MYMAGIC = 0xfeedbeef


def read(f):
    f.seek(0)
    f_header = '<I' + 12 * 'H' + 'II'
    magic, aversion, future1, future2, rawheadlen, rawreclen, hertz, sfuture1,\
        sfuture2, sfuture3, sfuture4, sfuture5, sfuture6,\
        sstarlen, tstatlen = struct.unpack(f_header,
                                           f.read(struct.calcsize(f_header)))
    if magic != MYMAGIC:
        raise Exception("Bad magic, wrong file type")
    f_endheader = '<I' + 10 * 'i'
    f.seek(rawheadlen - struct.calcsize(f_endheader))
    pagesize, supportedflags, osrel, osvers, ossub, ifuture1, ifuture2,\
        ifuture3, ifuture4, ifuture5, ifuture6 = \
        struct.unpack(f_endheader, f.read(struct.calcsize(f_endheader)))
    print osrel, osvers, ossub
    f.seek(rawheadlen)

    f_rawrecord = '<l' + 4 * 'H' + 19 * 'I'
    # FIXME it doesn't work
    # assert struct.calcsize(f_rawrecord) == rawreclen

    # photoproc.h
    f_tstat = '<' + 12 * 'i' + '16s??ill256s' + 8 * 'i'

    while True:
        rawrecord = f.read(struct.calcsize(f_rawrecord))
        if len(rawrecord) != struct.calcsize(f_rawrecord):
            break
        machin = struct.unpack(f_rawrecord, rawrecord)
        #ugly patch
        f.read(8)
        print machin
        curtime = machin[0]
        dt = datetime.datetime.fromtimestamp(curtime)
        now = int(time.time())
        print "age", (now - curtime) / (3600 * 24)
        scomplen = machin[6]
        pcomplen = machin[7]
        print scomplen
        print pcomplen
        ndeviat = machin[9]
        nactproc = machin[10]

        if scomplen:
            scomp = f.read(scomplen)
            sstat = zlib.decompress(scomp)
            # print sstat
        if pcomplen:
            pcomp = f.read(pcomplen)
            with open('/tmp/toto', 'w') as t:
                t.write(pcomp)
            pstat = zlib.decompress(pcomp)
            for a in range(0, len(pstat), tstatlen):
                s = pstat[a: a+tstatlen]
                tgid, pid, ppid, ruid, euid, suid, fsuid, rgid, egid, sgid, \
                    fsgid, nthr, name, isproc, state, excode, btime, elaps, \
                    cmdline, nthrslpi, nthrslpu, nthrrun, envid, ifuture1, \
                    ifuture2, ifuture3, ifuture4 \
                    = struct.unpack(f_tstat, s[:struct.calcsize(f_tstat)])
                name = name.rstrip('\x00')
                cmdline = cmdline.rstrip('\x00')
                print dt, name, cmdline


if __name__ == "__main__":
    import sys

    read(open(sys.argv[1], 'r'))
