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
import ConfigParser
import datetime
from dateutil.relativedelta import *

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
	print "Problem: [%s]\n" % e
	sys.exit(5)
    return resp

def getErrataPkgs(client, key, errata):
    # Get list of packages associated with given errata.
    errataresp = client.errata.listPackages(key, errata)
    return errataresp["id"]

def addErrataPkgs(client, key, target_channel, pkg_id):
    # Add packages to given RHN channel.
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


def errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end, rhsa):
    print "* Merging errata from %s to %s between dates %s and %s" % (src, dst, beginning, end)
    # band aid until config class can be created
    origin = src
    destination = dst
    advisories = []
    # Doing just RHSAs requires an entirely different method of populating the channels...
    if rhsa:
	tmpresult = sat_client.channel.software.listErrata(sat_sessionkey, origin, beginning, end)
	secadv = []
	#Only select RHSA advisories
	cmp = re.compile('^RHSA')
	for results in tmpresult:
	    if cmp.match(results["advisory_name"]):
		print "Adding Security Advisory [%s]\n" % results["advisory_name"]
		secadv.append(results["advisory_name"].strip())
	advisories = secadv
	mkBackup(advisories, "advisories")
	print "Cloning [%s] errata\n" % len(advisories)
	try:
	    result = sat_client.errata.cloneAsync(sat_sessionkey, destination, advisories)
	except Exception, e:
	    print "Error occurred. Errata cloning should continue asynchronously.\n"
    else:
	print "Generating errata list\n"
	try:
	    mergelist = sat_client.channel.software.listErrata(sat_sessionkey, origin, beginning, end)
	except Exception, e:
	    print "Error occurred generating list of errata to merge\n"
	    print "Error is [%s]\n" % e
	    sys.exit(1)
	mergeids = []
	for q in mergelist:
	    mergeids.append(q["id"])

	mkBackup(mergeids, "mergeid")
        try:
            result = mergeChannelErrata(sat_client, sat_sessionkey, origin, destination, beginning, end)
    	    if not result:
		rmBackup("mergeid")
		sys.exit("No errata to merge\n")

        except xmlrpclib.Fault, e:
            print "!!! Got XMLRPC Fault !!!\n\t%s" % e
            return XMLRPCERR
        print "\tErrata merged sucessfully"
	print "\tDisplaying results:\n\n\n"

	for results in result:
	    advisories.append(results["advisory_name"])
	print "full advisory list is [%s] items long\n" % len(advisories)

	mkBackup(advisories, "advisories")
	rmBackup("mergeid")


    # get list of packages from advisory list
    print "Building package list from [%s] advisories...\n" % len(advisories)
    pkgs = []
    try:
	for i in advisories:
	    pkgid = sat_client.errata.listPackages(sat_sessionkey,i)
	    print "Advisory is [%s]\n" % i
	    print "adding [%s] pkgids to list\n" % len(pkgid)
	    for a in pkgid:
		if a["providing_channels"]: 
	            pkgs.append(a["id"])
		else:
		    print "Skipping package:[%s]\t\tChannel:[%s]\n" % (a["id"], a["providing_channels"])
    except xmlrpclib.Fault, e:
	print "ERROR: XMLRPC Fault \n\t%s" % e
	return XMLRPCERR

    # dedupe array of packages
    uniqpkgs = []
    uniqpkgs = sorted(set(pkgs))

    mkBackup(uniqpkgs, "pkgids")
    rmBackup("advisories")

    # add packages to channel
    print "Adding [%s] packages to channel\n" % len(uniqpkgs)
    try:
    	print "Adding [%s] pkg IDs to channel [%s]\n" % (len(uniqpkgs),destination)
	addErrataPkgs(sat_client,sat_sessionkey,destination,uniqpkgs)
    except (xmlrpclib.Fault,xmlrpclib.ProtocolError), e:
	print "ERROR adding packages to channel [%s]: XMLRPC Fault \n\t%s" % (destination,e)
        print "Writing list of pkg IDs to recovery file.\n"
        return XMLRPCERR

    # log out of the satellite for good behavior
    rmBackup("pkgids")
###### END errataProcess ########

def parseConfig(config, chanlist, errtype):
    validcfg = []
    cfg = ConfigParser.ConfigParser()
    cfg.read(config)
    for src,dst in cfg.items(errtype):
	if src in chanlist and dst in chanlist:
	    validcfg.append((src,dst))
    return validcfg	
	

def main():
    SUCCESS = 0
    XMLRPCERR = 21
    UNSUPPORTED = 23
    SOCKERR = 27


    parser = OptionParser()
    parser.add_option("-u", "--username", dest="username", type="string", help="User login for satellite", metavar="USERNAME")
    parser.add_option("-p", "--password", dest="password", type="string", help="Password for specified user on satellite. If password is not specified it is read in during execution. If set to \"AUTO\", pwd is read from /etc/rhn/\$user-password", metavar="PASSWORD", default=None)
    parser.add_option("-s", "--server", dest="serverfqdn", type="string", help="FQDN of satellite server - omit https://", metavar="SERVERFQDN")
    parser.add_option("-o", "--origin", dest="origin", type="string", help="Specify the original channel label", metavar="ORIGIN", default=None)
    parser.add_option("-d", "--destination", dest="destination", type="string", help="Specify the destination channel label", metavar="DESTINATION", default=None)
    parser.add_option("-b", "--beginning", dest="beginning", type="string", help="Specify the beginning date. Date is in ISO 8601 (e.g. 2009-09-09) [Default: 2000-01-01", metavar="BEGINNING", default='2000-01-01')
    parser.add_option("-e", "--end", dest="end", type="string", help="Specify the end date. Date is in ISO 8601 (e.g. 2009-09-10 for Sept 10th, 2009). Use \"lastmonth\" to specify errata up to this day last month(used for cron typically).", metavar="END", default=None)
    parser.add_option("-S", "--rhsa-only", dest="rhsa_only", action="store_true", help="Only apply RHSA advisories", metavar="RHSA_ONLY", default=0)
    parser.add_option("-r", "--recovery", dest="recovery", action="store_true", help="Run script in recovery mode if previous run did not successfully complete", metavar="RECOVERY_MODE", default=0)
    parser.add_option("-c", "--config", dest="config", type="string", help="Specify list of source and destination channels to merge errata to.")

    (options, args) = parser.parse_args()

    if (options.config and (options.origin or options.destination)):
	print "ERROR: The config file and (source and/or destination) options are mutually exclusive. You must specify EITHER a source and destination channel, OR a config file containing a list of sources and destination channels for merge operations\n"
	return 100
    else:
	config = options.config

    if (options.origin and options.destination):
        origin = options.origin
        destination = options.destination

    if not ( options.username and options.serverfqdn and options.end ):
        print "Must specify login, server, and end date options. See usage:"
        parser.print_help()
        print "\nExample usage:\n"
        print "To merge errata from Red Hat channel to custom channel up to date 2009-09-09:\n\t%s -u admin -p password -s satellite.example.com -o rhel-x86_64-server-5 -d release-5-u1-server-x86_64 -e 2009-09-09\n" % sys.argv[0]
        print "To update channels specified in a config file, typically from cron:\n\t%s -u admin -p AUTO -s satellite.example.com -c ./config_file -e lastmonth\n" % sys.argv[0]
        print ""
        return 100
    else:
        login = options.username
        serverfqdn = options.serverfqdn
#        origin = options.origin
#        destination = options.destination
        beginning = options.beginning
	if options.end == "lastmonth":
	    end = str(datetime.date.today()+relativedelta(months=-1))
	    print "Calculated end date is: [%s]" % end
	else:
            end = options.end

	# If config file specified, ignore this option
	if options.config:
	    rhsa = options.rhsa_only
	else:
	    rhsa = options.rhsa_only
	recover = options.recovery

    if not options.password:
     password = getpass.getpass("%s's password:" % login)
    else:
	if options.password == "auto":
	    try:
		pf = open("/etc/rhn/%s-password" % login, "r")
		password = pf.readline()
		pf.close()
	    except:
		print "Unable to get password from /etc/rhn/%s-password\n" % login 
		sys.exit(100)
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

    #check if running in recovery mode
    if recover:
	print "Running in recovery mode. Beginning recovery...\n"
	recoverStart(sat_client, sat_sessionkey, destination)

    checkRecover()

    # Logic to loop over config file and process channel updates

    chanlist = []
    tmplist = sat_client.channel.listAllChannels(sat_sessionkey)
    for chan in tmplist:
	chanlist.append(chan["label"])

    allchans = parseConfig(config, chanlist, "ALL")

    for src,dst in allchans:
	print "Syncing source channel [%s] to destination channel [%s]\n" % (src,dst)
	errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end, rhsa)

    rhsachans = parseConfig(config, chanlist, "RHSA")
    rhsa = 1
    for src,dst in rhsachans:
	print "Syncing RHSA-only source channel [%s] to destination channel [%s]\n" % (src,dst)
	errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end, rhsa)
    

    print "* Logging out of the Satellite"
    try:
        satelliteLogout(sat_client, sat_sessionkey)
    except xmlrpclib.Fault, e:
        print "!!! Got XMLRPC fault !!!\n\t%s" % e
        return XMLRPCERR

    print "* Operation successful. Check Satellite console"
    return SUCCESS

if __name__ == "__main__":
    retval = 1
    try:
        retval = main()
    except KeyboardInterrupt:
        print "!!! Caught Ctrl-C !!!"

    print "\nExiting."
    sys.exit(retval)
