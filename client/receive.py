import socket
import struct
import time
import thread
import sys

sys.path.append('../include')
from constants import *

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
    packet, addr = s.recvfrom(1024)
    counter = counter + 1
