from constants import *

NUM_KEYS = 1000
kv = {}
# TODO use __FILE__
with open("../include/secret-cache.txt", "r") as f:
    f.read(1000)
    for x in range(NUM_KEYS):
        kv[x + 1] = f.read(VALUE_SIZE)
