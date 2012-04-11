#!/usr/bin/python
import argparse
import pprint
import os

class DSRR:
    hashalgs = {1: 'SHA-1', 2: 'SHA-256', 3: 'GOST'}
    rrname=''
    rrclass='IN'
    rrtype='DS'
    keyid=None
    keyalg=None
    hashalg=None
    digest=''
    ttl=0

    def __init__(self, rrtext):
        if not rrtext:
            return

        fields = rrtext.split()
        if len(fields) < 7:
            return

        self.rrname = fields[0].lower()
        fields = fields[1:]
        if fields[0].upper() in ['IN','CH','HS']:
            self.rrclass = fields[0].upper()
            fields = fields[1:]
        else:
            self.ttl = int(fields[0])
            self.rrclass = fields[1].upper()
            fields = fields[2:]

        if fields[0].upper() != 'DS':
            raise Exception

        self.rrtype = 'DS'
        self.keyid = int(fields[1])
        self.keyalg = int(fields[2])
        self.hashalg = int(fields[3])
        self.digest = ''.join(fields[4:]).upper()

    def __repr__(self):
        return('%s %s %s %d %d %d %s' %
                (self.rrname, self.rrclass, self.rrtype, self.keyid,
                self.keyalg, self.hashalg, self.digest))

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

class DLVRR:
    hashalgs = {1: 'SHA-1', 2: 'SHA-256', 3: 'GOST'}
    parent=''
    dlvname=''
    rrname='IN'
    rrclass='IN'
    rrtype='DLV'
    keyid=None
    keyalg=None
    hashalg=None
    digest=''
    ttl=0

    def __init__(self, rrtext, dlvname = 'dlv.isc.org'):
        if not rrtext:
            return

        fields = rrtext.split()
        if len(fields) < 7:
            return

        self.dlvname = dlvname.lower()
        parent = fields[0].lower().strip('.').split('.')
        parent.reverse()
        dlv = dlvname.split('.')
        dlv.reverse()
        while len(dlv) != 0 and len(parent) != 0 and parent[0] == dlv[0]:
            parent = parent[1:]
            dlv = dlv[1:]
        if len(dlv) != 0:
            raise Exception
        parent.reverse()
        self.parent = '.'.join(parent)
        self.rrname = self.parent + '.' + self.dlvname
        
        fields = fields[1:]
        if fields[0].upper() in ['IN','CH','HS']:
            self.rrclass = fields[0].upper()
            fields = fields[1:]
        else:
            self.ttl = int(fields[0])
            self.rrclass = fields[1].upper()
            fields = fields[2:]

        if fields[0].upper() != 'DLV':
            raise Exception

        self.rrtype = 'DLV'
        self.keyid = int(fields[1])
        self.keyalg = int(fields[2])
        self.hashalg = int(fields[3])
        self.digest = ''.join(fields[4:]).upper()

    def __repr__(self):
        return('%s %s %s %d %d %d %s' %
                (self.rrname, self.rrclass, self.rrtype,
                self.keyid, self.keyalg, self.hashalg, self.digest))

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

######################################################################
# Main
######################################################################
def main():
    zone='isc.org'
    zone = zone.strip('.')

    lookaside='dlv.isc.org'
    lookaside = lookaside .strip('.')

    #
    # Fetch DS records from DNS
    #
    dslist=[]
    fp=os.popen("/usr/local/bin/dig +noall +answer -t ds " + zone)
    for line in fp:
        dslist.append(DSRR(line))
    dslist = sorted(dslist, key=lambda ds: (ds.keyid, ds.keyalg, ds.hashalg))
    fp.close()

    #
    # Fetch DNSKEY records from DNS and generate DS records from them
    #
    dsklist=[]
    fp=os.popen("/usr/local/bin/dig +noall +answer -t dnskey " + zone +
                " | /usr/local/sbin/dnssec-dsfromkey -f - " + zone)
    for line in fp:
        dsklist.append(DSRR(line))
    fp.close()

    #
    # Compare real DS values to generated values
    #
    found = False
    for ds in dsklist:
        if ds in dslist:
            print ("DS for KSK %s/%03d/%05d (%s) found in parent" %
                   (ds.rrname.strip('.'), ds.keyalg,
                    ds.keyid, DSRR.hashalgs[ds.hashalg]))
            found = True

    if not found:
        print ("No DS records found covering %s/DNSKEY" % zone)

    if found or not lookaside:
        exit(0 if found else 1)

    #
    # Fetch DLV records from DNS
    #
    dlvlist=[]
    fp=os.popen("/usr/local/bin/dig +noall +answer -t dlv " +
                zone + '.' + lookaside)
    for line in fp:
        dlvlist.append(DLVRR(line))
    dlvlist = sorted(dlvlist,
                     key=lambda dlv: (dlv.keyid, dlv.keyalg, dlv.hashalg))
    fp.close()

    #
    # Fetch DNSKEY records from DNS and generate DLV records from them
    #
    dlvklist=[]
    fp=os.popen("/usr/local/bin/dig +noall +answer -t dnskey " + zone +
                " | /usr/local/sbin/dnssec-dsfromkey -f - -l " +
                lookaside + ' ' + zone)
    for line in fp:
        dlvklist.append(DLVRR(line))
    fp.close()

    #
    # Compare real DLV values to generated values
    #
    for dlv in dlvklist:
        if dlv in dlvlist:
            print ("DLV for KSK %s/%03d/%05d (%s) found in %s" %
                   (dlv.parent, dlv.keyalg, dlv.keyid,
                    DLVRR.hashalgs[dlv.hashalg], dlv.dlvname))
            found = True

    if not found:
        print ("No DLV records found covering %s/DNSKEY" % zone)

    exit(0 if found else 1)


if __name__ == "__main__":
    main()
