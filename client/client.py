import socket
import struct
import time
import thread
import sys
from collections import deque
import random
import math
import threading

sys.path.append('../include')
from constants import *
from headers import *
from db import kv


path_query = "query.txt"
num_query = 1000000
zipf = 0.99

len_key = 16
len_val = 128
max_key = 1000


#Zipf
zeta = [0.0]
for i in range(1, max_key + 1):
    zeta.append(zeta[i - 1] + 1 / pow(i, zipf))
field = [0] * (num_query + 1)
k = 1
for i in range(1, num_query + 1):
    if (i > num_query * zeta[k] / zeta[max_key]):
        k = k + 1
    field[i] = k

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("base", help="base ip", type=int)
parser.add_argument("num", help="number of threads", type=int)
parser.add_argument('--nosharding', action='store_true', default=False, help='no sharding')
parser.add_argument('--badsharding', action='store_true', default=False, help='bad sharding')
args = parser.parse_args()

SERVER_A = "10.0.0.1"
SERVER_B = "10.0.0.2"
no_sharding = args.nosharding
bad_sharding = args.badsharding
def get_shard(key):
    if no_sharding:
        return SERVER_A
    if bad_sharding:
        if (key / 100) % 2 == 0:
            return SERVER_A
        else:
            return SERVER_B
    if key % 2 == 0:
        return SERVER_A
    else:
        return SERVER_B

responses = 0
def worker(ip=None):
    global responses 
    use_zipf = True
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, NC_PORT))
    while (True):
        if use_zipf:
            r = random.randint(1, num_query)
            key_header = field[r]
        else:
            key_header = random.randint(1, max_key)
        key_field = struct.pack(">I", key_header)
        for x in range(len_key - 4):
            key_field += "\0"
        rq_p = P4NetCache(type=NC_READ_REQUEST, key=key_field)
        s.sendto(str(rq_p), (get_shard(key_header), NC_PORT))
        packet_str, src = s.recvfrom(1024)
        nc_p = P4NetCache(packet_str)
        if nc_p.type != NC_READ_REPLY:
            print "unexpected response"
            break
        key_header = struct.unpack(">I", nc_p.key[:4])[0]
        if key_header < 1 or key_header > 1000:
            print "invalid key %d" % key_header
            break
        if nc_p.value != kv[key_header]:
            print "data mismatch on key %d" % key_header
            print "expected:"
            print kv[key_header]
            break
        responses += 1
    nc_p.show()

from threading import Thread
for x in range(args.num):
    ip = "10.0.0.%d" % (x + args.base)
    print ip
    t = Thread(target=worker, kwargs={"ip": ip})
    t.setDaemon(True)
    t.start()


last_print = time.time()
while (True):
    time.sleep(1)
    duration = time.time() - last_print
    print "QPS = %f" % (responses / duration)
    responses = 0
    last_print = time.time()

