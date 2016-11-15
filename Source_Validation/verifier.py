#!/usr/bin/env python
import SimpleHTTPServer
import SocketServer
import time, sys
import hashlib, os, urllib2

SERVER = ''
KEY = 'CS460'
TABLE = {}
VALIDATION = 5 # second


class myHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Perform garbage collection if necessary 
        if len(TABLE) > 10000:
            for nonce in TABLE.items():
                if time.time() > TABLE[nonce]['validation']:
                    del TABLE[nonce]
                
	# the http host is generic 
        # Generate a client-specific hostname
	if self.path == '/':
            client = str(self.client_address[0])

            # random nonce
            nonce = hashlib.sha256(os.urandom(64)).hexdigest()
            if nonce not in TABLE:
                TABLE[nonce] = {}
                TABLE[nonce]['validation'] = time.time() + VALIDATION
                TABLE[nonce]['fresh'] = True

            ts = str(time.time() + VALIDATION)
            MAC = hashlib.sha256(nonce + '|' + ts + '|' + client + '|' + KEY).hexdigest()
            hostname = nonce + '|' + ts + '|' + MAC
            #print hostname

	    self.send_response(302)
       	    self.send_header('Location', SERVER + str(hostname) + '.html')
       	    self.end_headers()

        else:
            client = str(self.client_address[0])
            specific_hostname = urllib2.unquote(self.path)
            # remove the '/' at the beginning and '.html' at the end
            specific_hostname = specific_hostname[1:]
            specific_hostname = specific_hostname[:len(specific_hostname)-5]
            #print specific_hostname


            valid = True
            if '|' in specific_hostname:
                [nonce, ts, MAC] = specific_hostname.split('|')
                #print nonce
                #print ts
                #print MAC

                # varification
                if time.time() < float(ts):
                    if nonce in TABLE:

                        if (time.time() < TABLE[nonce]['validation']) and TABLE[nonce]['fresh']:
                            TABLE[nonce]['fresh'] = False

                            if MAC != hashlib.sha256(nonce + '|' + ts + '|' + client + '|' + KEY).hexdigest():
                                valid = False
                                print 'incorrect MAC'

                        else:
                            valid = False
                            print 'unfresh nonce'
                    else:
                        valid = False
                        print 'expired nonce'
                else:
                    print 'invalid nonce'
                    valid = False
            else:
                valid = False


            # verify the client-specific hostname
            if valid:
                f = open('b.html')
                #send code 200 response
                self.send_response(200)
                #send header first
                self.send_header('Content-type','text-html')
                self.end_headers()
                #send file content to client
                self.wfile.write(f.read())
                f.close()
            else:
                f = open('c.html')
                #send code 200 response
                self.send_response(200)
                #send header first
                self.send_header('Content-type','text-html')
                self.end_headers()
                #send file content to client
                self.wfile.write(f.read())
                f.close()

            
	    
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage sudo python server.py server_address'
    else:
        global SERVER
        SERVER = 'http://' + str(sys.argv[1]) + '/'
        PORT = 80
        SocketServer.TCPServer.allow_reuse_address = True
        handler = SocketServer.TCPServer(("", PORT), myHandler)
        print "serving at port 80"
        handler.serve_forever()
