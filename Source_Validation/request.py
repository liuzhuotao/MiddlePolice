#!/usr/bin/env python

import httplib
import urllib, urllib2

httplib.HTTPConnection.debuglevel = 1

page = urllib.urlopen('http://YOUR_SERVER')
print page.read()

