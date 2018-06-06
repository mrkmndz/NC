import socket
import struct
import time
import thread
import sys
from collections import deque
import random
import math

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

sent_counter = 0
recv_counter = 0
def counting():
    while True:
        print sent_counter , recv_counter
        time.sleep(1)
thread.start_new_thread(counting, ())

def sender():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query_rate = 1000
    interval = 1.0 / (query_rate + 1)
    while True:
        r = random.randint(1, num_query)
        key_header = field[r]
        key_field = struct.pack(">I", key_header)
        for x in range(len_key - 4):
            key_field.append("\0")
        rq_p = NetCache(type=NC_READ_REQUEST, key=key_field)
        o_lock.acquire()
        outstanding[key_header].append(time.time())
        o_lock.release()
        s.sendto(str(rq_p), (SERVER_IP, NC_PORT))
        sent_counter = sent_counter + 1
        time.sleep(interval)

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
    if key_header < 1 or key_header > 1000:
        print "invalid key %d" % key_header
        nc_p.show()
        break
    if nc_p[DataValue].value != kv[key_header]:
        print "data mismatch on key %d" % key_header
        nc_p.show()
        print "vs"
        print kv[key_header]
        break
    o_lock.acquire()
    sent_times = outstanding[key_header]
    if len(sent_times) == 0:
        print "recv without send %d" % key_header
        break
    oldest = sent_times.popleft()
    o_lock.release()
    this_latency = time.time() - oldest
    if this_latency > max_latency:
        print "max latency is %f" % this_latency
    recv_counter = recv_counter + 1
