import socket
import struct
import time
import thread
import sys
import time

sys.path.append('/home/ubuntu/NetCache/bmv2/tools')
from bm_runtime.simple_pre import SimplePre
from bm_runtime.standard import Standard
import bmpy_utils as utils

client, mc_client = utils.thrift_connect(
    "localhost", 22222, 
    [("standard", Standard.Client), ("simple_pre", SimplePre.Client)]
)

from nc_config import *

NC_PORT = 8888
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CONTROLLER_IP = "10.0.0.3"
path_hot = "hot.txt"
path_log = "controller_log.txt"

len_key = 16
len_val = 128

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((CONTROLLER_IP, NC_PORT))
s.settimeout(1)

## Initiate the switch
op = NC_UPDATE_REQUEST
op_field = struct.pack("B", op)
f = open(path_hot, "r")
for line in f.readlines():
    line = line.split()
    key_header = line[0]
    key_body = line[1:]
    
    key_header = int(key_header)
    for i in range(len(key_body)):
        key_body[i] = int(key_body[i], 16)
    
    key_field = ""
    key_field += struct.pack(">I", key_header)
    for i in range(len(key_body)):
        key_field += struct.pack("B", key_body[i])
    
    packet = op_field + key_field
    s.sendto(packet, (SERVER_IP, NC_PORT))
    time.sleep(0.001)
f.close()

last_reset = time.time()
while True:
    try:
        packet, addr = s.recvfrom(2048)
        op_field = packet[0]
        key_field = packet[1:len_key + 1]
        load_field = packet[len_key + 1:]
        
        op = struct.unpack("B", op_field)[0]
        if (op != NC_HOT_READ_REQUEST):
            continue
        
        key_header = struct.unpack(">I", key_field[:4])[0]
        load = struct.unpack(">IIII", load_field)
        
        print "\tHot Item:", key_header, load

        rq_op_field = struct.pack("B", NC_UPDATE_REQUEST)
        rq_key_field = ""
        rq_key_field += struct.pack(">I", key_header)
        for i in range(12):
            rq_key_field += struct.pack("B", 0)
        rq_packet = rq_op_field + rq_key_field
        s.sendto(rq_packet, (SERVER_IP, NC_PORT))
        print "sent request"
    except socket.timeout:
        print "t/o"

    if time.time() - last_reset > 15:
        print "RESETTING"
        for x in range(1, 5):
            register_name = "hh_load_%d_reg" % x
            print "resetting "  + register_name
            client.bm_register_reset(0, register_name)
        for x in range(1, 4):
            register_name = "hh_bf_%d_reg" % x
            print "resetting "  + register_name
            client.bm_register_reset(0, register_name)
        last_reset = time.time()
