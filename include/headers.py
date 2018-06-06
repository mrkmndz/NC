from scapy.all import *

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

class DataValue(Packet):
    name = "NetCache Value"
    fields_desc = [
        StrFixedLenField('value', None, length=128)
    ]

bind_layers(NetCache, HotItemLoad, type=NC_HOT_READ_REQUEST)
bind_layers(NetCache, HotItemLoad, type=NC_READ_REPLY)
bind_layers(NetCache, HotItemLoad, type=NC_UPDATE_REPLY)


