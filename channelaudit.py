#!/usr/bin/env python


##To-Do:
#1. build channel listing

from satellite import *
import xmlrpclib
import getpass
import socket
import re
from optparse import OptionParser

def parseList(filename):
    srvfile = open(filename,'r')
    srvlist = srvfile.readlines()
    srvfile.close()
    reg = re.compile("linux", re.IGNORECASE)
    omslist = []
    linuxlist = []
    for m in srvlist:
	if ( reg.search(m) ):
		linuxlist.append(m)
    for i in linuxlist:
	ddd = i.split(",")
	omslist.append({'name':ddd[1],'oms':ddd[14]})
    return omslist

def getArch(sat_client,sat_sessionkey,id):
    cpu = sat_client.system.getCpu(sat_sessionkey,id)
    return cpu["arch"]

def getOS(sat_client,sat_sessionkey,id):
    os = sat_client.system.getDetails(sat_sessionkey,id)
    return os["release"]

def main():

    parser = OptionParser()
    parser.add_option("-u", "--username", dest="username", type="string", help="User login for satellite", metavar="USERNAME")
    parser.add_option("-p", "--password", dest="password", type="string", help="Password for specified user on satellite. If password is not specified it is read in during execution", metavar="PASSWORD", default=None)
    parser.add_option("-s", "--server", dest="serverfqdn", type="string", help="FQDN of satellite server - omit https://", metavar="SERVERFQDN")
    parser.add_option("-l", "--list", dest="auditlist", type="string", help="List of servers to audit, as pulled from normandy's nightly cmdb hostlist")

    (options, args) = parser.parse_args()
    if not ( options.username and options.auditlist ):
        print "Must specify valid Satellite login and serverlist to audit.  See usage:"
        parser.print_help()
        print "\nExample usage:\n"
        print "This is an example of the command\n\t./channelaudit.py -u admin"
        print ""
        return 100
    else:
        login = options.username
	if not ( options.serverfqdn ):
	    serverfqdn = "localhost"
	else:
            serverfqdn = options.serverfqdn

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

    print "Auditing attached channels for server list provided\n"

    satservers = sat_client.system.listSystems(sat_sessionkey)
    cmdblist = parseList("/home/vyq577/newest_td_extract.csv")

    for p in satservers:
	print "Name: [%s]\tID: [%s]\n" % (p["name"],p["id"])
    

if __name__ == "__main__":
    main()
