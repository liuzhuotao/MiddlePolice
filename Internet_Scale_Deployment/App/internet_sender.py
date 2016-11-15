#!/usr/bin/env python

import socket, sys, select, threading
import datetime
import pprint

# The number of files posted to the server
FLOW_COUNT = 200

class Sender:
    def __init__(self, saddr, daddr, dport, flow_size):
        self.flow_size = flow_size
        self.saddr = saddr
        self.daddr = socket.gethostbyname(daddr)
        self.dport = dport
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.send_sock.bind((self.saddr, 0)) # send the source address
        self.send_sock.connect((self.daddr, self.dport))

    def sending_traffic(self):
        message = bytearray(b'\x00' * 99999) # 100KB
        message.append('D')

        startTime = datetime.datetime.now()

        self.send_sock.send(message) # Sending flows 
            
        # waiting for message to come back
        while True:
            ready = select.select([self.send_sock], [], [], 0.00001)
            if ready[0]:
                data = self.send_sock.recv(9000)
                if 'END' in data:
                    break

        endTime = datetime.datetime.now()
        fct = endTime - startTime

        #print 'FCT is ' + str(fct.total_seconds()) 
        return fct.total_seconds()



if __name__=='__main__':
    if len(sys.argv) == 1:
        # Specify your server IP
        dst = 'XXXX'
    else:
        dst = sys.argv[1]
    
    fct_result = {'result': []}

    sender = Sender("", dst, 9877, 1)
    counter = 0
    while counter < FLOW_COUNT:
        counter += 1
        fct = sender.sending_traffic()
        print fct
        fct_result['result'].append(fct)

    # close the socket
    sender.send_sock.close()

    f = open('home_network_reroute_to_victim.py', 'w+')
    pprint.pprint(fct_result, f)
    f.close()

