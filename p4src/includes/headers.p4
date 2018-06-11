header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}


header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header nc_hdr_t {
    bit<8> op;
    bit<128> key;
}

header nc_load_t {
    bit<32> load_1;
    bit<32> load_2;
    bit<32> load_3;
    bit<32> load_4;
}

struct Parsed_packet {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    nc_hdr_t nc_hdr;
    nc_load_t nc_load;
}

/*
    The headers for value are defined in value.p4
    k = 1, 2, ..., 8
    header nc_value_{k}_t {
        fields {
            value_{k}_1: 32;
            value_{k}_2: 32;
            value_{k}_3: 32;
            value_{k}_4: 32;
        }
    }
*/