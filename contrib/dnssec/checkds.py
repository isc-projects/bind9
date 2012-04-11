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
# checkds:
# Fetch DS RRset for the given zone from the DNS; fetch DNSKEY
# RRset from the masterfile if specified, or from DNS if not.
# Generate a set of expected DS records from the DNSKEY RRset,
# and report on congruency.
######################################################################
def checkds(zone, masterfile = None):
    dslist=[]
    fp=os.popen("/usr/local/bin/dig +noall +answer -t ds " + zone)
    for line in fp:
        dslist.append(DSRR(line))
    dslist = sorted(dslist, key=lambda ds: (ds.keyid, ds.keyalg, ds.hashalg))
    fp.close()

    dsklist=[]

    if masterfile:
        fp = os.popen("/usr/local/sbin/dnssec-dsfromkey -f %s %s " %
                      (masterfile, zone))
    else:
        fp = os.popen("/usr/local/bin/dig +noall +answer -t dnskey " + zone +
                      " | /usr/local/sbin/dnssec-dsfromkey -f - " + zone)

    for line in fp:
        dsklist.append(DSRR(line))

    fp.close()

    found = False
    for ds in dsklist:
        if ds in dslist:
            print ("DS for KSK %s/%03d/%05d (%s) found in parent" %
                   (ds.rrname.strip('.'), ds.keyalg,
                    ds.keyid, DSRR.hashalgs[ds.hashalg]))
            found = True

    if not found:
        print ("No DS records found covering %s/DNSKEY" % zone)

    return found

######################################################################
# checkdlv:
# Fetch DLV RRset for the given zone from the DNS; fetch DNSKEY
# RRset from the masterfile if specified, or from DNS if not.
# Generate a set of expected DLV records from the DNSKEY RRset,
# and report on congruency.
######################################################################
def checkdlv(zone, lookaside, masterfile = None):
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
    if masterfile:
        fp = os.popen("/usr/local/sbin/dnssec-dsfromkey -f %s -l %s %s " %
                      (masterfile, lookaside, zone))
    else:
        fp = os.popen("/usr/local/bin/dig +noall +answer -t dnskey %s "
                      " | /usr/local/sbin/dnssec-dsfromkey -f - -l %s %s"
                      % (zone, lookaside, zone))

    for line in fp:
        dlvklist.append(DLVRR(line))

    fp.close()

    found = False
    for dlv in dlvklist:
        if dlv in dlvlist:
            print ("DLV for KSK %s/%03d/%05d (%s) found in %s" %
                   (dlv.parent, dlv.keyalg, dlv.keyid,
                    DLVRR.hashalgs[dlv.hashalg], dlv.dlvname))
            found = True

    if not found:
        print ("No DLV records found covering %s/DNSKEY" % zone)

    return found


######################################################################
# parse_args:
# Read command line arguments, set global 'args' structure
######################################################################
def parse_args():
    global args
    parser = argparse.ArgumentParser(description='checkds: checks DS coverage')

    parser.add_argument('zone', type=str, help='zone to check')
    parser.add_argument('-f', '--file', dest='masterfile', type=str,
                        help='zone master file')
    parser.add_argument('-l', '--lookaside', dest='lookaside', type=str,
                        help='DLV lookaside zone')
    parser.add_argument('-v', '--version', action='version', version='9.9.1')
    args = parser.parse_args()

    args.zone = args.zone.strip('.')
    if args.lookaside:
        lookaside = args.lookaside.strip('.')

######################################################################
# Main
######################################################################
def main():
    parse_args()

    if args.lookaside:
        found = checkdlv(args.zone, args.lookaside, args.masterfile)
    else:
        found = checkds(args.zone, args.masterfile)

    exit(0 if found else 1)

if __name__ == "__main__":
    main()
