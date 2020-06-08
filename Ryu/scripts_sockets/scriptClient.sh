#!/bin/bash

import socket
import struct
import sys
import os
import subprocess

message = 'Join multicast group in mode SSM'
message2 = 'Leave multicast group in mode SSM'
server = socket.gethostbyname('provider1-socket')
server_conn = (server, 1000)

multicast_group = sys.argv[2]
mode = sys.argv[1]
server_source = sys.argv[3]

# Create the datagram socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP:DGRAM, TCP:STREAM

try:
    # Send data to the multicast group
    print >>sys.stderr, 'sending "%s"' % message
    sock.sendto(message, server_conn)
    sock.sendto(multicast_group, server_conn)
    
    # Look for responses from all recipients
    while True:
        print >>sys.stderr, 'waiting to receive confirmation from server'
        data, server = sock.recvfrom(100)
        print >>sys.stderr, 'received "%s" from %s' % (data, server)
        data_server, server = sock.recvfrom(100)

        if mode=='SSM':
            if (multicast_group == data_server):
                os.system("sudo mcfirst -4 -I eth1 %s %s 1234 -c 10" % (server_source, multicast_group))
                print >>sys.stderr, 'sending "%s"' % message2
                sock.sendto(message2, server_conn)
                break
            else:
                data, server = sock.recvfrom(100)
                print >>sys.stderr, data
                break
        else:
            print('Introduce a mode')
except:
    print("An exception occurred")

finally:
    print >>sys.stderr, 'closing socket'
    sock.sendto('closing', server_conn)
    sock.close()
