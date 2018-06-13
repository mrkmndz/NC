import socket
import struct
import time
import thread
import sys
import time
from cStringIO import StringIO
import re

from scapy.all import *

sys.path.append('../include')
from constants import *
from headers import *
import threading


CACHE_SIZE = 50
EVICTION_SIZE = 5
CACHE_EXIST_TABLE = "check_cache_exist"
CACHE_EXIST_ACTION = "check_cache_exist_act"
CACHE_VALID_REGISTER = "cache_valid_reg"

def configure_runtime_api():
    sys.path.append('../bmv2/tools')
    from bm_runtime.simple_pre import SimplePre
    from bm_runtime.standard import Standard
    import bmpy_utils as utils
    from runtime_CLI import RuntimeAPI, load_json_config

    client, mc_client = utils.thrift_connect(
        "localhost", 22222, 
        [("standard", Standard.Client), ("simple_pre", SimplePre.Client)]
    )

    load_json_config(client, None)
    return RuntimeAPI(SimplePre, client, mc_client)

def reset_hh_regs(api):
    print "RESETTING HH REGS"
    api.do_register_reset("hh_load_1_reg")
    api.do_register_reset("hh_bf_1_reg")

def reset_cache_allocation(api):
    print "RESETTING CACHE ALLOCATION TABLE"
    api.do_table_clear(CACHE_EXIST_TABLE)
    api.do_register_reset(CACHE_VALID_REGISTER)

def add_table_entry(api, key, value):
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    api.do_table_add("%s %s %s => %d" % (CACHE_EXIST_TABLE, CACHE_EXIST_ACTION, key, value))
    sys.stdout = old_stdout
    output = mystdout.getvalue()
    print output
    handle_search = re.search('Entry has been added with handle (.*)', output)
    return int(handle_search.group(1))

def invalidate_cache(api, index):
    api.do_register_write("%s %d 0" % (CACHE_VALID_REGISTER, index))

def remove_table_entry(api, handle):
    api.do_table_delete("%s %d" % (CACHE_EXIST_TABLE, handle))

lock = threading.Lock()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
api = configure_runtime_api()
reset_hh_regs(api)
reset_cache_allocation(api)
cache = [None for x in range(CACHE_SIZE)]

def send(pkt):
    sendp(pad_pkt(pkt, 64), iface="eth0")

def recv(pkt):
    if not pkt.haslayer(P4NetCache):
        return
    nc_p = pkt[P4NetCache]
    if nc_p.type != NC_READ_REQUEST:
        return

    lock.acquire()
    try:
        open_slot = next(idx for idx, val in enumerate(cache) if val is None)
        print "found slot at %d" % open_slot
        encoded_key = '0x' + ''.join(x.encode('hex') for x in nc_p.key)
        print "for key %s" % encoded_key
        handle = add_table_entry(api, encoded_key, open_slot)
        cache[open_slot] = (encoded_key, handle)
        rq_p = P4NetCache(type=NC_UPDATE_REQUEST, key=nc_p.key, value="aaa")
        s.sendto(str(rq_p), (SERVER_IP, NC_PORT))
    except StopIteration:
        print "cache is full"
        choices = random.sample(range(CACHE_SIZE), EVICTION_SIZE)
        cstrs = map(lambda x : "%d" % x, choices)
        print "evicting %s" % (", ".join(cstrs))
        for choice in choices:
            key, handle = cache[choice]
            print "uncaching %s" % key
            invalidate_cache(api, choice)
            remove_table_entry(api, handle)
            cache[choice] = None
        reset_hh_regs(api)
    lock.release()

sniff(iface="eth0", prn=recv, count=0)
