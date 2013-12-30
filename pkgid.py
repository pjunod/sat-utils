#!/usr/bin/env python
###
###
###    To-DO
###	1. finish recovery functions
###	2. modify start to check for recovery files -- done
###	3. add option to process recovery files -- done
###	4. add section for RHSA advisories only -- done
###	5. add config file for defining channels to clone/merge

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
import logging
from satellite import *

def main():
    SUCCESS = 0
    XMLRPCERR = 21
    UNSUPPORTED = 23
    SOCKERR = 27


    parser = OptionParser()
    parser.add_option("-u", "--username", dest="username", type="string", help="User login for satellite", metavar="USERNAME")
    parser.add_option("-p", "--password", dest="password", type="string", help="Password for specified user on satellite. If password is not specified it is read in during execution", metavar="PASSWORD", default=None)
    parser.add_option("-s", "--server", dest="serverfqdn", type="string", help="FQDN of satellite server - omit https://", metavar="SERVERFQDN")
    parser.add_option("-l", "--list", dest="pkgidlist", type="string", help="List of pkgids to get pkg names", metavar="PKGIDLIST")

    (options, args) = parser.parse_args()

    if not ( options.username and options.serverfqdn and options.pkgidlist):
        print "Must specify login, server, and list of pkgids. See usage:"
        parser.print_help()
        print "\nExample usage:\n"
	print "To get the name and arch of a given list of package IDs: %s -u admin -s localhost -l pkgidlist.txt\n" % sys.argv[0]
        return 100
    else:
        login = options.username
        serverfqdn = options.serverfqdn
	pkgidfile = options.pkgidlist

    if not options.password:
     password = getpass.getpass("%s's password:" % login)
    else:
     password = options.password

    # login to the satellite to get our client obj and session key
    print "* Logging into RHN Satellite"
    try:
        (sat_client, sat_sessionkey) = satelliteLogin(login, password, serverfqdn)
    except (xmlrpclib.Fault,xmlrpclib.ProtocolError), e:
        print "!!! Got XMLRPC error !!!\n\t%s" % e
        print "!!! Check Satellite FQDN and login information; You can also look at /var/log/httpd/error_log on the Satellite for more info !!!"
        return XMLRPCERR
    except socket.error, e:
        print "!!! Got socket error !!!\n\n%s" % e
        print "!!! Could not connect to %s" % serverfqdn
        return SOCKERR

    # check to see if we're supported
    print "* Checking if Satellite supports necessary calls"
    try:
        if isSupported(sat_client):
            print "\tSupported version of Satellite"
        else:
            print "\n!!! Unsupported version of Satellite !!!\n!!! Requires Satellite >= v%s !!!" % SUPPORTED_SATELLITE_VERSION
            return UNSUPPORTED
    except xmlrpclib.Fault, e:
        print "!!! Got XMLRPC fault\n\t%s" % e
        return XMLRPCERR

    pkgidlist = []
    try:
   	fh = open(pkgidfile)
    except IOError, e:
	print e
	sys.exit(200)

    for i in iter(fh.readline, ''):
        pkgidlist.append(i.rstrip())

    for id in pkgidlist:
        pkgname = sat_client.packages.getDetails(sat_sessionkey, int(id))
	print "ID: [%s]\tArch: [%s]\tName: [%s]" % (id, pkgname["arch_label"], pkgname["name"])

if __name__ == "__main__":
    retval = 1
    try:
        retval = main()
    except KeyboardInterrupt:
        print "!!! Caught Ctrl-C !!!"

    print "\nExiting."
    sys.exit(retval)
