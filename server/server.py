import socket
import struct
import time
import thread
import sys

sys.path.append('../include')
from constants import *
from headers import *
from db import kv

def lookup_val(key):
    key_header = struct.unpack(">I", key[:4])[0]
    return kv[key_header]

counter = 0
def counting():
    last_counter = 0
    while True:
        print (counter - last_counter), counter
        last_counter = counter
        time.sleep(1)
thread.start_new_thread(counting, ())

speed = 1000

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((SERVER_IP, NC_PORT))
while True:
    packet_str, src = s.recvfrom(2048)
    src_ip, src_port = src
    nc_p = P4NetCache(packet_str)
    
    if (nc_p.type == NC_READ_REQUEST or nc_p.type == NC_HOT_READ_REQUEST):
        rp_p = P4NetCache(type=NC_READ_REPLY, key=nc_p.key, value=lookup_val(nc_p.key))
        time.sleep(1/speed)
        s.sendto(str(rp_p), (src_ip, NC_PORT))
        counter = counter + 1
    elif (nc_p.type == NC_UPDATE_REQUEST):
        rp_p = P4NetCache(type=NC_UPDATE_REPLY, key=nc_p.key, value=lookup_val(nc_p.key))
        time.sleep(1/speed)
        s.sendto(str(rp_p), (CONTROLLER_IP, NC_PORT))
