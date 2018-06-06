import socket
import struct
import time
import thread
import sys

sys.path.append('../include')
from constants import *

path_kv = "kv.txt"
path_log = "server_log.txt"

len_key = 16
len_val = 128

f = open(path_kv, "r")
lines = f.readlines()
f.close()

kv = {}
for i in range(2, 3002, 3):
    line = lines[i].split();
    key_header = line[0]
    key_body = line[1:]
    val = lines[i + 1].split()
    
    key_header = int(key_header)
    for i in range(len(key_body)):
        key_body[i] = int(key_body[i], 16)
    for i in range(len(val)):
        val[i] = int(val[i], 16)
    
    key_field = ""
    key_field += struct.pack(">I", key_header)
    for i in range(len(key_body)):
        key_field += struct.pack("B", key_body[i])
    
    val_field = ""
    for i in range(len(val)):
        val_field += struct.pack("B", val[i])
    
    kv[key_header] = (key_field, val_field)
f.close()

def lookup_val(key):
    key_header = struct.unpack(">I", nc_p.key[:4])[0]
    op_field = struct.pack("B", op)
    key_field, val_field = kv[key_header]
    return val_field

counter = 0
def counting():
    last_counter = 0
    while True:
        print (counter - last_counter), counter
        last_counter = counter
        time.sleep(1)
thread.start_new_thread(counting, ())

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((SERVER_IP, NC_PORT))
while True:
    packet_str, src = s.recvfrom(2048)
    nc_p = NetCache(packet_str)
    
    if (nc_p.type == NC_READ_REQUEST or op == NC_HOT_READ_REQUEST):
        rp_p = NetCache(type=NC_READ_REPLY, key=nc_p.key) / \
                DataValue(value=lookup_val(nc_p.key))
        s.sendto(str(rq_p), (CLIENT_IP, NC_PORT))
        counter = counter + 1
    elif (op == NC_UPDATE_REQUEST):
        rp_p = NetCache(type=NC_UPDATE_REPLY, key=nc_p.key) / \
                DataValue(value=lookup_val(nc_p.key))
        s.sendto(str(rq_p), (CONTROLLER_IP, NC_PORT))
