#define ETHER_TYPE_IPV4 0x0800
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17


parser TopParser(packet_in b,
             out Parsed_packet p,
             out user_metadata_t user_metadata,
             out digest_data_t digest_data, //TODO: Devon check these extra meta data fields to see if they're actually needed
             inout sume_metadata_t sume_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        b.extract (p.ethernet);
        transition select (latest.etherType) {
            ETHER_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        b.extract(p.ipv4);
        transition select (latest.protocol) {
            IPV4_PROTOCOL_TCP: parse_tcp;
            IPV4_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        b.extract (p.tcp);
        transition accept;
    }

    state parse_udp {
        b.extract (p.udp);
        transition select (latest.dstPort) {
            NC_PORT: parse_nc_hdr;
            default: accept;
        }
    }

    state parse_nc_hdr {
        b.extract (p.nc_hdr);
        transition select(latest.op) {
            NC_READ_REQUEST: accept;
            NC_READ_REPLY: parse_value;
            NC_HOT_READ_REQUEST: parse_nc_load;
            NC_UPDATE_REQUEST: accept;
            NC_UPDATE_REPLY: parse_value;
            default: accept;
        }
    }

    state parse_nc_load {
        b.extract (p.nc_load);
        transition accept;
    }

    state parse_value {
        transition parse_nc_value_1;
    }

    /*
        The parsers for value headers are defined in value.p4
        k = 1, 2, ..., 8
        parser parse_value_{k} {
            b.extract (p.nc_value_{k});
            transition select(k) {
                8: accept;
                default: parse_value_{k + 1};
            }
        }
    */

}