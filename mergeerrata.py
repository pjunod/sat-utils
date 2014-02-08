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
from optparse import OptionGroup
import ConfigParser
import datetime
from dateutil.relativedelta import *
from satellite import *
import logging

def mkBackup(backup, bktype):
    r = open('/var/satellite/scripts/%s.rec' % bktype, 'w')
    for id in backup:
        r.write('%s\n' % id)

def rmBackup(bktype):
    os.remove('/var/satellite/scripts/%s.rec' % bktype)

def mergeChannelErrata(client, key, origin_channel, dest_channel, start_date, end_date):
    logger = logging.getLogger(__name__)
    try:
        resp = client.channel.software.mergeErrata(key, origin_channel, dest_channel, start_date, end_date)
    except Exception, e:
        #define path for log files and rec files in config
        logger.critical("Problem occurred merging errata.")
        logger.exception(e)
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
    logger = logging.getLogger(__name__)
    recNeeded = glob.glob('/var/satellite/scripts/*.rec')
    for recFile in recNeeded:
        if os.path.isfile(recFile):
            #Recovery files found. Need to run in recovery mode
            logger.critical("Recovery files found in /var/satellite/scripts/. Rerun script in recovery mode")
            sys.exit(255)

def recoverStart(sat_client, sat_sessionkey, dst):
    logger = logging.getLogger(__name__)
    if os.path.isfile("/var/satellite/scripts/pkgids.rec"):
        logger.info("Package ID recovery file found. Reprocessing....")
        z = open("/var/satellite/scripts/pkgids.rec", 'r')
        entries = z.readlines()
        z.close()
        logger.debug("entries type is [%s]" % type(entries))
        for a in entries:
            logger.debug("Recovery adding pkgid [%s]" % a.strip())
            addErrataPkgs(sat_client,sat_sessionkey,dst,int(a.strip()))
    else:
        logger.critical("This part not yet written. You should probably go find Paul....")
        sys.exit(100)


def errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end, rhsa=0):
    logger = logging.getLogger(__name__)
    logger.info("Merging errata from %s to %s between dates %s and %s" % (src, dst, beginning, end))
    src_details = sat_client.channel.software.getDetails(sat_sessionkey, src)
    src_arch = src_details["arch_name"]
    logger.debug("Source arch is [%s].\n" % src_arch)
    advisories = []
    mergelist = sat_client.channel.software.listErrata(sat_sessionkey, src, beginning, end)

    ### For backup/resume purposes
    mergeids = []
    for q in mergelist:
        mergeids.append(q["id"])
    mkBackup(mergeids, "mergeid")

    # Filter out just RHSAs for security-only updates
    if rhsa:
        cmp = re.compile('^RHSA')
        for results in mergelist:
            if cmp.match(results["advisory_name"]):
                logger.debug("Adding Security Advisory [%s]\n" % results["advisory_name"])
                advisories.append(results["advisory_name"].strip())

    else:
	for results in mergelist:
	    advisories.append(results["advisory_name"].strip())

    mkBackup(advisories, "advisories")

    logger.info("Cloning [%s] errata\n" % len(advisories))

    try:
        result = sat_client.errata.cloneAsync(sat_sessionkey, dst, advisories)
	if not result:
	    rmBackup("mergeid")
	    logger.warn("No errata to merge")
    except Exception, e:
        logger.warn("Error occurred. Errata cloning should continue asynchronously.")

    logger.info("Errata merged sucessfully")
    logger.info("full advisory list is [%s] items long\n" % len(advisories))

    mkBackup(advisories, "advisories")
    rmBackup("mergeid")


    # get list of packages from advisory list
    logger.info("Building package list from [%s] advisories...\n" % len(advisories))
    pkgs = []
    try:
        for i in advisories:
            pkgid = sat_client.errata.listPackages(sat_sessionkey,i)
            logger.debug("Advisory is [%s]" % i)
            logger.debug("adding [%s] pkgids to list" % len(pkgid))
            for a in pkgid:
                if a["providing_channels"]:
                    logger.debug("Pkg [%s] channel validated." % a["id"])
                    if src in a["providing_channels"]:
                        logger.debug("Pkg [%s] arch [%s] validated." % (a["id"],a["providing_channels"]))
                        pkgs.append(a["id"])
                    else:
                        logger.debug("Skipping package:[%s], Invalid arch." % a["id"])
                        logger.debug("Providing channels: [%s]" % a["providing_channels"])
                else:
                    logger.debug("Skipping package:[%s]\t\tChannel:[%s]\n" % (a["id"], a["providing_channels"]))
    except xmlrpclib.Fault, e:
        logger.critical("ERROR: XMLRPC Fault")
        logger.exception(e)
        return XMLRPCERR

    # dedupe array of packages
    uniqpkgs = []
    uniqpkgs = sorted(set(pkgs))

    mkBackup(uniqpkgs, "pkgids")
    rmBackup("advisories")

    # add packages to channel
    try:
        logger.info("Adding [%s] pkg IDs to channel [%s]\n" % (len(uniqpkgs),dst))
        addErrataPkgs(sat_client,sat_sessionkey,dst,uniqpkgs)
    except (xmlrpclib.Fault,xmlrpclib.ProtocolError), e:
        logger.critical("ERROR adding packages to channel [%s]" % dst)
        logger.critical("Writing list of pkg IDs to recovery file.")
        logger.exception(e)
        return

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

def showHelp(parser):
    parser.print_help()
    print "\nExample usage:\n"
    print "To merge errata from Red Hat channel to custom channel up to date 2009-09-09:\n\t%s -u admin -p password -s satellite.example.com -o rhel-x86_64-server-5 -d release-5-u1-server-x86_64 -e 2009-09-09\n" % sys.argv[0]
    print "To update channels specified in a config file, typically from cron:\n\t%s -u admin -p AUTO -s satellite.example.com -c ./config_file -e lastmonth\n" % sys.argv[0]

    print "######Logging#####\n\n"
    print "Specified loglevel must be one of:\n"
    print "\t\tinfo (default)\n\t\twarning\n\t\terror\n\t\tcritical\n\t\tdebug\n"

def main():
    SUCCESS = 0
    XMLRPCERR = 21
    UNSUPPORTED = 23
    SOCKERR = 27

    LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}

    parser = OptionParser()
    parser.add_option("-u", "--username", dest="username", type="string", help="User login for satellite", metavar="USERNAME")
    parser.add_option("-p", "--password", dest="password", type="string", help="Password for specified user on satellite. If password is not specified it is read in during execution. If set to \"AUTO\", pwd is read from /etc/rhn/$user-password", metavar="PASSWORD", default=None)
    parser.add_option("-s", "--server", dest="serverfqdn", type="string", help="FQDN of satellite server - omit https://", metavar="SERVERFQDN")
    parser.add_option("-o", "--origin", dest="origin", type="string", help="Specify the original channel label", metavar="ORIGIN", default=None)
    parser.add_option("-d", "--destination", dest="destination", type="string", help="Specify the destination channel label", metavar="DESTINATION", default=None)
    parser.add_option("-b", "--beginning", dest="beginning", type="string", help="Specify the beginning date. Date is in ISO 8601 (e.g. 2009-09-09) [Default: 2000-01-01]", metavar="BEGINNING", default='2000-01-01')
    parser.add_option("-e", "--end", dest="end", type="string", help="Specify the end date. Date is in ISO 8601 (e.g. 2009-09-10 for Sept 10th, 2009). Use \"lastmonth\" to specify errata up to this day last month(used for cron typically).", metavar="END", default=None)
    parser.add_option("-S", "--rhsa-only", dest="rhsa_only", action="store_true", help="Only apply RHSA advisories", metavar="RHSA_ONLY", default=0)
    parser.add_option("-r", "--recovery", dest="recovery", action="store_true", help="Run script in recovery mode if previous run did not successfully complete", metavar="RECOVERY_MODE", default=0)
    parser.add_option("-c", "--config", dest="config", type="string", help="Specify list of source and destination channels to merge errata to.")
    parser.add_option("-l", "--loglevel", dest="loglevel", type="string", help="Specify the log level for the script to run under.")

    (options, args) = parser.parse_args()

    if options.loglevel:
        loglevel = options.loglevel
        print "log level specified on cmdline\n"
    else:
        loglevel = logging.INFO
        print "defaulting to INFO level logging.\n"

    LOG_FILENAME = '/var/log/mergeerrata.log'
    formatter = logging.Formatter( "%(asctime)s %(levelname)s - %(message)s", datefmt='%Y-%m-%d %H:%M:%S' )

    logger = logging.getLogger(__name__)
    try:
        logger.setLevel(loglevel)
    except Exception, e:
        print "Invalid logging level specified. See logging help section.\n"
        showHelp(parser)
        sys.exit(300)

    try:
        logfile = logging.FileHandler(LOG_FILENAME)
        logfile.setLevel(loglevel)
        logfile.setFormatter(formatter)
        logger.addHandler(logfile)
        if os.isatty(sys.stdout.fileno()):
            #Attach stdout logger if running from a console
            conlog = logging.StreamHandler()
            conlog.setLevel(loglevel)
            conlog.setFormatter(formatter)
            logger.addHandler(conlog)

    except Exception, e:
        print "Failed setting up logging.\n\nError: %s\n" % e
        sys.exit(300)

    logger.info("%s starting" % sys.argv[0])

    if (options.config and (options.origin or options.destination)):
        logger.critical("The config file and (source and/or destination) options are mutually exclusive. You must specify EITHER a source and destination channel, OR a config file containing a list of sources and destination channels for merge operations")
	showHelp(parser)
        return 100

    config = options.config

    if (options.origin and options.destination):
        src = options.origin
        dst = options.destination
    elif (options.config):
        logger.info("Config file specified")
    else:
        logger.critical("Source and destination must both be specified")
	showHelp(parser)
        return 100

    if not ( options.username and options.serverfqdn and options.end ):
        logger.critical("Must specify login, server, and end date options. See usage")
        showHelp(parser)
        print ""
        return 100
    else:
        login = options.username
        serverfqdn = options.serverfqdn
        beginning = options.beginning
        if options.end == "lastmonth":
            end = str(datetime.date.today()+relativedelta(months=-1))
            logger.debug("Calculated end date is: [%s]" % end)
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
                logger.critical("Unable to get password from /etc/rhn/%s-password\n" % login)
                sys.exit(100)
        else:
            password = options.password

    # login to the satellite to get our client obj and session key
    logger.info("Logging into RHN Satellite")
    try:
        (sat_client, sat_sessionkey) = satelliteLogin(login, password, serverfqdn)
    except (xmlrpclib.Fault,xmlrpclib.ProtocolError), e:
        logger.critical("!!! Got XMLRPC error !!!")
        logger.critical("!!! Check Satellite FQDN and login information; You can also look at /var/log/httpd/error_log on the Satellite for more info !!!")
        logger.exception(e)
        return XMLRPCERR
    except socket.error, e:
        logger.critical("!!! Got socket error !!!")
        logger.critical("!!! Could not connect to %s" % serverfqdn)
        logger.exception(e)
        return SOCKERR

    # check to see if we're supported
    logger.debug("Checking if Satellite supports necessary calls")
    try:
        if isSupported(sat_client):
            logger.debug("Supported version of Satellite")
        else:
            logger.critical("!!! Unsupported version of Satellite !!!\n!!! Requires Satellite >= v%s !!!" % SUPPORTED_SATELLITE_VERSION)
            return UNSUPPORTED
    except xmlrpclib.Fault, e:
        logger.critical("!!! Got XMLRPC fault\n\t%s")
        logger.exception(e)
        return XMLRPCERR

    #check if running in recovery mode
    if recover:
        logger.warn("Running in recovery mode. Beginning recovery...")
        recoverStart(sat_client, sat_sessionkey, dst)

    checkRecover()

    # Logic to loop over config file and process channel updates

    if config:
        chanlist = []
        tmplist = sat_client.channel.listAllChannels(sat_sessionkey)
        for chan in tmplist:
            chanlist.append(chan["label"])

        try:
            allchans = parseConfig(config, chanlist, "ALL")
        except Exception:
            allchans = 0
            logger.warn("Section [ALL] not found. Skipping...")

        if allchans:
            for src,dst in allchans:
                logger.info("Syncing source channel [%s] to destination channel [%s]\n" % (src,dst))
                errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end)

        try:
            rhsachans = parseConfig(config, chanlist, "RHSA")
        except Exception:
            rhsachans = 0
            logger.warn("Section [RHSA] not found. Skipping...")

        if rhsachans:
            rhsa = 1
            for src,dst in rhsachans:
                logger.info("Syncing RHSA-only source channel [%s] to destination channel [%s]\n" % (src,dst))
                errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end, rhsa)

    else:
        errataProcess(sat_client, sat_sessionkey, src, dst, beginning, end)

    logger.info("Logging out of the Satellite")
    try:
        satelliteLogout(sat_client, sat_sessionkey)
    except xmlrpclib.Fault, e:
        logger.critical("!!! Got XMLRPC fault !!!")
        logger.exception(e)
        return XMLRPCERR

    return SUCCESS

if __name__ == "__main__":
    retval = 1
    try:
        retval = main()
    except KeyboardInterrupt:
        print "!!! Caught Ctrl-C !!!"

    print "\nExiting."
    sys.exit(retval)
