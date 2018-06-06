import socket
import struct
import time
import thread
import sys
import time

sys.path.append('/home/ubuntu/NetCache/bmv2/tools')
from bm_runtime.simple_pre import SimplePre
from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *
from runtime_CLI import RuntimeAPI, load_json_config
import bmpy_utils as utils

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

CACHE_SIZE = 10
CACHE_EXIST_TABLE = "check_cache_exist"
CACHE_EXIST_ACTION = "check_cache_exist_act"

def reset_hh_regs(client):
    print "RESETTING HH REGS"
    for x in range(1, 5):
        register_name = "hh_load_%d_reg" % x
        print "resetting "  + register_name
        api.do_register_reset(register_name)
    for x in range(1, 4):
        register_name = "hh_bf_%d_reg" % x
        print "resetting "  + register_name
        api.do_register_reset(register_name)

def reset_cache_allocation(client):
    print "RESETTING CACHE ALLOCATION TABLE"
    api.do_table_clear(CACHE_EXIST_TABLE)

def add_table_entry(client, key, key_bw, value, value_bw):
    encoded_key = bytes_to_string(parse_param(key, key_bw))
    param = BmMatchParam(type = BmMatchParamType.EXACT,
                         exact = BmMatchParamExact(encoded_key))
    data = [bytes_to_string(parse_param(value, value_bw))]
    self.client.bm_mt_add_entry(
        0, CACHE_EXIST_TABLE, [param], CACHE_EXIST_ACTION, data,
        BmAddEntryOptions(priority = 0)
    )

def add_table_entry_simple(api, key, value):
    api.do_table_add("%s %s %s => %d" % (CACHE_EXIST_TABLE, CACHE_EXIST_ACTION, key, value))



s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((CONTROLLER_IP, NC_PORT))
s.settimeout(1)

reset_hh_regs(client)
reset_cache_allocation(client)
cache = [None for x in range(CACHE_SIZE)]
last_reset = time.time()
while True:
    try:
        packet_str, src = s.recvfrom(2048)

        nc_p = NetCache(packet_str)

        if (nc_p.type != NC_HOT_READ_REQUEST):
            continue

        nc_p.show()

        try:
            open_slot = next(idx for idx, val in enumerate(cache) if val is None)
            encoded_key = '0x' + ''.join(x.encode('hex') for x in nc_p.key)
            print encoded_key
            add_table_entry_simple(api, encoded_key, open_slot)
        except StopIteration:
            print "cache is full"

        rq_p = NetCache(type=NC_UPDATE_REQUEST, key=nc_p.key)
        s.sendto(str(rq_p), (SERVER_IP, NC_PORT))
        print "sent request"
    except socket.timeout:
        print "t/o"

    if time.time() - last_reset > 5:
        reset_hh_regs(client)
        last_reset = time.time()
