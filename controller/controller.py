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
from runtime_CLI import RuntimeAPI, load_json_config

client, mc_client = utils.thrift_connect(
    "localhost", 22222, 
    [("standard", Standard.Client), ("simple_pre", SimplePre.Client)]
)

load_json_config(client, None)
api = RuntimeAPI(SimplePre, client, mc_client)

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

CACHE_SIZE = 50
CACHE_EXIST_TABLE = "check_cache_exist"
CACHE_EXIST_ACTION = "check_cache_exist_act"
CACHE_VALID_REGISTER = "cache_valid_reg"

def reset_hh_regs(api):
    print "RESETTING HH REGS"
    for x in range(1, 5):
        register_name = "hh_load_%d_reg" % x
        print "resetting "  + register_name
        api.do_register_reset(register_name)
    for x in range(1, 4):
        register_name = "hh_bf_%d_reg" % x
        print "resetting "  + register_name
        api.do_register_reset(register_name)

def reset_cache_allocation(api):
    print "RESETTING CACHE ALLOCATION TABLE"
    api.do_table_clear(CACHE_EXIST_TABLE)
    api.do_register_reset(CACHE_VALID_REGISTER)

def add_table_entry_simple(api, key, value):
    api.do_table_add("%s %s %s => %d" % (CACHE_EXIST_TABLE, CACHE_EXIST_ACTION, key, value))



s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((CONTROLLER_IP, NC_PORT))
s.settimeout(1)

reset_hh_regs(api)
reset_cache_allocation(api)
cache = [None for x in range(CACHE_SIZE)]
last_reset = time.time()
while True:
    try:
        packet_str, src = s.recvfrom(2048)

        nc_p = NetCache(packet_str)

        if (nc_p.type != NC_HOT_READ_REQUEST):
            continue

        #nc_p.show()

        try:
            open_slot = next(idx for idx, val in enumerate(cache) if val is None)
            print "found slot at %d" % open_slot
            encoded_key = '0x' + ''.join(x.encode('hex') for x in nc_p.key)
            cache[open_slot] = encoded_key
            print encoded_key
            add_table_entry_simple(api, encoded_key, open_slot)
            rq_p = NetCache(type=NC_UPDATE_REQUEST, key=nc_p.key)
            s.sendto(str(rq_p), (SERVER_IP, NC_PORT))
            print "sent request"
        except StopIteration:
            print "cache is full"

    except socket.timeout:
        print "t/o"

    if time.time() - last_reset > 10000:
        reset_hh_regs(api)
        last_reset = time.time()
