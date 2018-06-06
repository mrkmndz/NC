import socket
import struct
import time
import thread
import sys

sys.path.append('../include')
from constants import *
from headers import *
from db import kv

counter = 0
def counting():
    last_counter = 0
    while True:
        print (counter - last_counter), counter
        last_counter = counter
        time.sleep(1)
thread.start_new_thread(counting, ())

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((CLIENT_IP, NC_PORT))
while True:
    packet_str, src = s.recvfrom(1024)
    nc_p = NetCache(packet_str)
    if DataValue not in nc_p:
        print "missing data"
        nc_p.show()
        break
    key_header = struct.unpack(">I", nc_p.key[:4])[0]
    if nc_p[DataValue].value != kv[key_header]:
        print "data mismatch on key %d" % key_header
        nc_p.show()
        print "vs"
        print kv[key_header]
        break
    counter = counter + 1
