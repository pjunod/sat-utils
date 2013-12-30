#!/usr/bin/python

import rpm
import re
import os
import sys
import ConfigParser
import datetime
import logging

#open xls list
#2. load packages and validate
#3. open current patch list
#4. add pkg if newer and remove old pkg
#5. check for dupes and old versions
#6. validate version-locked groups
#7. save list

def getList(fileName):
    pkgfile = open(fileName)
    rawlist = pkgfile.readlines()
    pkglist = []
    for i in rawlist:
        pkglist.append(i.rstrip())
    #print "pkglist is: \n %s" % pkglist
    #sys.exit(0)
    pkgfile.close()
    pkgindex = []
    outputlist = []
    print "Getting index of list\n"
    inst = pkglist.index('Installing:')
    upd = pkglist.index('Updating:')
    dep = pkglist.index('Installing for dependencies:')

    print "index value of installing is [%s]\n" % inst
    print "index value of updating is [%s]\n" % upd
    print "index value of deps is [%s]\n" % dep
    rpmpkg = re.compile('^\s\w.*$')
    for pkg in pkglist[inst+1:]:
        if rpmpkg.match(pkg):
            print "pkg matches [%s]\n" % pkg
            outputlist.append(pkg.strip())
        else:
            print "pkg does not match: [%s]\n" % pkg
            break
    for pkg in pkglist[upd+1:]:
        if rpmpkg.match(pkg):
            print "update package matches [%s]\n" % pkg
            outputlist.append(pkg.strip())
        else:
            print "line does not match: [%s]\n" % pkg
            break
    for pkg in pkglist[dep+1:]:
        if rpmpkg.match(pkg):
            print "deps package matches [%s]\n" % pkg
            outputlist.append(pkg.strip())
        else:
            print "line does not match: [%s]\n" % pkg
            break
            
    print "outputlist is as follows:\n\n"
    for a in outputlist:
        print "%s\n" % a

    sys.exit(0)
#    print "Getting packages to be installed...\n"
#    installing = re.compile('^Installing:$')
#    for index, entry in enumerate(pkglist):
#        if not installing.match(entry):
#            continue
#        else 
#            
#    updating = re.compile('^Updating:$')
#    deps = re.compile('^Installing for dependencies:$')
#
#    for entry in pkglist.readlines():
#        if installing.match(entry) or updating.match(entry) or deps.match(entry)
#            print "Adding packages:\n"
#            

getList(sys.argv[1])
