#!/usr/bin/env python

import struct
import zlib
import datetime

MYMAGIC = 0xfeedbeef


class ProcessStat(object):
    tgid = None
    pid = None
    ppid = None
    ruid = None
    euid = None
    suid = None
    fsuid = None
    rgid = None
    egid = None
    sgid = None
    fsgid = None
    nthr = None
    name = None
    isproc = None
    state = None
    excode = None
    btime = None
    elaps = None
    cmdline = None
    nthrslpi = None
    nthrslpu = None
    nthrrun = None
    envid = None
    ifuture1 = None
    ifuture2 = None
    ifuture3 = None
    ifuture4 = None


class ProcessStats(object):

    def __init__(self, pstat, tstatlen):
        self.pstat = pstat
        self.tstatlen = tstatlen

    def __iter__(self):
        # photoproc.h
        f_tstat = '<12i16s??ill256s8i'
        for a in range(0, len(self.pstat), self.tstatlen):
            s = self.pstat[a: a+self.tstatlen]
            r = ProcessStat()
            r.tgid, r.pid, r.ppid, r.ruid, r.euid, r.suid, r.fsuid, r.rgid, \
                r.egid, r.sgid, r.fsgid, r.nthr, r.name, r.isproc, r.state, \
                r.excode, r.btime, r.elaps, r.cmdline, r.nthrslpi, r.nthrslpu, \
                r.nthrrun, r.envid, r.ifuture1, r.ifuture2, r.ifuture3, \
                r.ifuture4 = struct.unpack(f_tstat,
                                           s[:struct.calcsize(f_tstat)])
            r.name = r.name.strip('\x00')
            r.cmdline = r.cmdline.strip('\x00')
            yield r


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
            return ProcessStats(zlib.decompress(self.pcomp), self.tstatlen)

        raise AttributeError('%s is missing' % key)


class Atop(object):

    def __init__(self, f):
        self.f = f
        self.f.seek(0)
        f_header = '<I12HII'
        magic, aversion, future1, future2, rawheadlen, rawreclen, hertz, sfuture1,\
            sfuture2, sfuture3, sfuture4, sfuture5, sfuture6,\
            sstarlen, tstatlen = struct.unpack(f_header,
                                               f.read(struct.calcsize(f_header)))
        if magic != MYMAGIC:
            raise Exception("Bad magic, wrong file type")
        self.tstatlen = tstatlen

        f_endheader = '<I10i'
        self.f.seek(rawheadlen - struct.calcsize(f_endheader))
        pagesize, supportedflags, osrel, osvers, ossub, ifuture1, ifuture2,\
            ifuture3, ifuture4, ifuture5, ifuture6 = \
            struct.unpack(f_endheader, f.read(struct.calcsize(f_endheader)))
        self.f.seek(rawheadlen)

        self.f_rawrecord = '<l4H19I'
        # FIXME it doesn't work
        # assert struct.calcsize(f_rawrecord) == rawreclen

        # photoproc.h
        self.f_tstat = '<12i16s??ill256s8i'

    def __iter__(self):
        while True:
            rawrecord = self.f.read(struct.calcsize(self.f_rawrecord))
            if len(rawrecord) != struct.calcsize(self.f_rawrecord):
                # It's the end of the archive.
                break
            machin = struct.unpack(self.f_rawrecord, rawrecord)
            # ugly patch
            self.f.read(8)
            curtime = machin[0]
            dt = datetime.datetime.fromtimestamp(curtime)
            scomplen = machin[6]
            pcomplen = machin[7]
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
            print "%s [%s] %s" % (stat.curtime, s.name, s.cmdline)
