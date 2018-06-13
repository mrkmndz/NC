from scapy.all import *
from constants import *

nc_types = {
    NC_READ_REQUEST     : "read request",
    NC_READ_REPLY       : "read reply",
    NC_HOT_READ_REQUEST : "hot read request",
    #NC_WRITE_REQUEST    : "write request",
    #NC_WRITE_REPLY      : "write reply",
    NC_UPDATE_REQUEST   : "update request",
    NC_UPDATE_REPLY     : "update reply"
}

class NetCache(Packet):
    name = 'NetCache'
    fields_desc = [
        ByteEnumField('type', None, nc_types),
        StrFixedLenField('key', None, length=KEY_SIZE),
        StrFixedLenField('value', None, length=VALUE_SIZE)
    ]

class ZeroChecksumUDP(UDP):
    def post_build(self, p, pay):
        self.chksum = 0
        return super(ZeroChecksumUDP, self).post_build(p, pay)

bind_layers(UDP, NetCache, dport=NC_PORT)
bind_layers(ZeroChecksumUDP, NetCache, dport=NC_PORT)

