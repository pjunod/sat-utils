#!/usr/bin/env python

import getpass
import socket
import sys
import time
import xmlrpclib
import re
import signal
import os
import glob
from optparse import OptionParser

SUPPORTED_SATELLITE_VERSION = '5.2.0'

def satelliteLogin(sat_login, sat_passwd, sat_fqdn):
    # input: string login, string passwd, string fqdn
    # returns: string session key

    sat_url = "https://%s/rpc/api" % sat_fqdn
    client = xmlrpclib.Server(sat_url, verbose=0)
    key = client.auth.login(sat_login, sat_passwd)

    return (client, key)

def satelliteLogout(client, key):
    # input: session key
    # returns: error value from logout

    return client.auth.logout(key)

def isSupported(client):
    # input: xmlrpc client, session key
    # returns: boolean for supported satellite version

    if client.api.systemVersion() >= SUPPORTED_SATELLITE_VERSION:
        return True

    return False

def mkBackup(backup, bktype):
    r = open('/var/satellite/scripts/%s.rec' % bktype, 'w')
    for id in backup:
	r.write('%s\n' % id)

def rmBackup(bktype):
    os.remove('/var/satellite/scripts/%s.rec' % bktype)

def mergeChannelErrata(client, key, origin_channel, dest_channel, start_date, end_date):
    try:
        resp = client.channel.software.mergeErrata(key, origin_channel, dest_channel, start_date, end_date)
    except Exception, e:
	#define path for log files and rec files in config
	print "Problem occurred merging errata.\n"
	sys.exit(5)
    return resp

#def getAdvisories(client, key, advisories):
#    advresp = client.errata.

def getErrataPkgs(client, key, errata):
    errataresp = client.errata.listPackages(key, errata)
    return errataresp["id"]

def addErrataPkgs(client, key, target_channel, pkg_id):
    pkgresp = client.channel.software.addPackages(key, target_channel, pkg_id)
    return pkgresp

def checkRecover():
    recNeeded = glob.glob('/var/satellite/scripts/*.rec')
    for recFile in recNeeded:
	if os.path.isfile(recFile):
	    #Recovery files found. Need to run in recovery mode
	    print "Recovery files found in /var/satellite/scripts/. Rerun script in recovery mode\n"
	    sys.exit(255)

def recoverStart(sat_client, sat_sessionkey, destination):
    if os.path.isfile("/var/satellite/scripts/pkgids.rec"):
	print "Package ID recovery file found. Reprocessing....\n"
	z = open("/var/satellite/scripts/pkgids.rec", 'r')
	entries = z.readlines()
	z.close()
	print "entries type is [%s]\n" % type(entries)
	for a in entries:
	    print "Recovery adding pkgid [%s]\n" % a.strip()
	    addErrataPkgs(sat_client,sat_sessionkey,destination,int(a.strip()))
    else:
        print "This part not yet written. You should probably go find Paul....\n"
        sys.exit(100)

