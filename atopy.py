#!/usr/bin/env python

import struct
import zlib
import time
import datetime

MYMAGIC = 0xfeedbeef


class ProcessStat(object):

    def __init__(self, pstat, tstatlen, f_tstat):
        self.pstat = pstat
        self.tstatlen = tstatlen
        self.f_tstat = f_tstat

    def __iter__(self):
        for a in range(0, len(self.pstat), self.tstatlen):
            s = self.pstat[a: a+self.tstatlen]
            tgid, pid, ppid, ruid, euid, suid, fsuid, rgid, egid, sgid, \
                fsgid, nthr, name, isproc, state, excode, btime, elaps, \
                cmdline, nthrslpi, nthrslpu, nthrrun, envid, ifuture1, \
                ifuture2, ifuture3, ifuture4 \
                = struct.unpack(self.f_tstat, s[:struct.calcsize(self.f_tstat)])
            name = name.strip('\x00')
            cmdline = cmdline.strip('\x00')
            yield name, cmdline


class Stat(object):

    def __init__(self, curtime, scomp, pcomp, tstatlen, f_tstat):
        self.curtime = curtime
        self.scomp = scomp
        self.pcomp = pcomp
        self.tstatlen = tstatlen
        self.f_tstat = f_tstat

    def __getattr__(self, key):
        if key == 'system':
            return zlib.decompress(self.scomp)
        if key == 'process':
            return ProcessStat(zlib.decompress(self.pcomp), self.tstatlen,
                               self.f_tstat)

        raise AttributeError('%s is missing' % key)


class Atop(object):

    def __init__(self, f):
        self.f = f
        self.f.seek(0)
        f_header = '<I' + 12 * 'H' + 'II'
        magic, aversion, future1, future2, rawheadlen, rawreclen, hertz, sfuture1,\
            sfuture2, sfuture3, sfuture4, sfuture5, sfuture6,\
            sstarlen, tstatlen = struct.unpack(f_header,
                                            f.read(struct.calcsize(f_header)))
        if magic != MYMAGIC:
            raise Exception("Bad magic, wrong file type")
        self.tstatlen = tstatlen

        f_endheader = '<I' + 10 * 'i'
        self.f.seek(rawheadlen - struct.calcsize(f_endheader))
        pagesize, supportedflags, osrel, osvers, ossub, ifuture1, ifuture2,\
            ifuture3, ifuture4, ifuture5, ifuture6 = \
            struct.unpack(f_endheader, f.read(struct.calcsize(f_endheader)))
        print osrel, osvers, ossub
        self.f.seek(rawheadlen)

        self.f_rawrecord = '<l' + 4 * 'H' + 19 * 'I'
        # FIXME it doesn't work
        # assert struct.calcsize(f_rawrecord) == rawreclen

        # photoproc.h
        self.f_tstat = '<' + 12 * 'i' + '16s??ill256s' + 8 * 'i'

    def __iter__(self):
        while True:
            rawrecord = self.f.read(struct.calcsize(self.f_rawrecord))
            if len(rawrecord) != struct.calcsize(self.f_rawrecord):
                break
            machin = struct.unpack(self.f_rawrecord, rawrecord)
            #ugly patch
            self.f.read(8)
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
                scomp = self.f.read(scomplen)
            else:
                scomp = None
            if pcomplen:
                pcomp = self.f.read(pcomplen)
            else:
                pcomp = None
            yield Stat(dt, scomp, pcomp, self.tstatlen, self.f_tstat)


if __name__ == "__main__":
    import sys

    a = Atop(open(sys.argv[1], 'r'))
    for stat in a:
        for s in stat.process:
            print stat.curtime, s
