#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/parsers.p4"
#include "includes/checksum.p4"

#include "cache.p4"
#include "heavy_hitter.p4"
#include "value.p4"
#include "ipv4.p4"
#include "ethernet.p4"

control ingress {
    process_cache();
    process_value();
    
    ipv4_route.apply();
}

control egress {
    if (nc_hdr.op == NC_READ_REQUEST and nc_cache_md.cache_exist != 1) {
        heavy_hitter();
    }
    ethernet_set_mac.apply();
}