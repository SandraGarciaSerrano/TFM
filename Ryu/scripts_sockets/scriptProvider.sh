#!/usr/bin/python

import socket
import sys
import os
import subprocess
import time

mode = sys.argv[1]
multicast_group = sys.argv[2]

#server_ip = socket.gethostbyname('client1')
server_address = ('', 1000)

# Create the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to the server address
sock.bind(server_address) #Need to bind to the external network interface

# Receive/respond loop
while True:
    print >>sys.stderr, '\nwaiting for clients'
    data, address = sock.recvfrom(1024)

    print >>sys.stderr, 'received %s bytes from %s' % (len(data), address)
    print >>sys.stderr, data

    server, address = sock.recvfrom(1024)
    print >>sys.stderr, server

    sock.sendto('Listening', address)
    sock.sendto(multicast_group, address)
    print >>sys.stderr, '\nListening on %s' % (multicast_group)

    if mode == 'SSM':
        if (multicast_group == server):
            time.sleep(1)

            command = 'sudo mcsender -t3 %s:1234 -ieth1' % (multicast_group)
            process = subprocess.Popen(command, shell=True)
            data, address = sock.recvfrom(1024)
            print >>sys.stderr, data
            
            print >>sys.stderr, '\nNo more clients'
            process = subprocess.Popen("killall -9 mcsender", shell=True)
            break
        else:
            print(address)
            sock.sendto('Not a valid group address', address)
            print >>sys.stderr, '\nNot a valid group address'
            break
    else:
        print('Introduce a mode')

  
	

