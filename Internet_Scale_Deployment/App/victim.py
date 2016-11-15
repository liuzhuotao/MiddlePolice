#!/usr/bin/env python

import socket, sys
import datetime

from twisted.internet import protocol, reactor, endpoints

class Echo(protocol.Protocol):
    def dataReceived(self, data):
        if 'D' in data:
            self.transport.write('END')

class EchoFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return Echo()

endpoints.serverFromString(reactor, "tcp:9877").listen(EchoFactory())
reactor.run()
