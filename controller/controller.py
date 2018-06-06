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

from scapy.all import *

nc_types = {
    NC_READ_REQUEST     : "read request",
    NC_READ_REPLY       : "read reply",
    NC_HOT_READ_REQUEST : "hot read request",
    NC_WRITE_REQUEST    : "write request",
    NC_WRITE_REPLY      : "write reply",
    NC_UPDATE_REQUEST   : "update request",
    NC_UPDATE_REPLY     : "update reply"
}

class NetCache(Packet):
    name = 'NetCache'
    fields_desc = [
        ByteEnumField('type', None, nc_types),
        StrFixedLenField('key', None, length=16),
    ]

class HotItemLoad(Packet):
    name = "Hot Item Load Values"
    fields_desc = [
        IntField('load_1', None),
        IntField('load_2', None),
        IntField('load_3', None),
        IntField('load_4', None)
    ]

bind_layers(NetCache, HotItemLoad, type=NC_HOT_READ_REQUEST)

NC_PORT = 8888
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CONTROLLER_IP = "10.0.0.3"

len_key = 16
len_val = 128

def reset_hh_regs(client):
    print "RESETTING"
    for x in range(1, 5):
        register_name = "hh_load_%d_reg" % x
        print "resetting "  + register_name
        client.bm_register_reset(0, register_name)
    for x in range(1, 4):
        register_name = "hh_bf_%d_reg" % x
        print "resetting "  + register_name
        client.bm_register_reset(0, register_name)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((CONTROLLER_IP, NC_PORT))
s.settimeout(1)

reset_hh_regs(client)
last_reset = time.time()
while True:
    try:
        packet_str, src = s.recvfrom(2048)

        nc_p = NetCache(packet_str)

        if (nc_p.type != NC_HOT_READ_REQUEST):
            continue

        nc_p.show()

        rq_p = NetCache(type=NC_UPDATE_REQUEST, key=nc_p.key)
        s.sendto(str(rq_p), (SERVER_IP, NC_PORT))
        print "sent request"
    except socket.timeout:
        print "t/o"

    if time.time() - last_reset > 3:
        reset_hh_regs(client)
        last_reset = time.time()
