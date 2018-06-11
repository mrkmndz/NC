action set_egress(egress_spec) {
   standard_metadata.egress_spec = egress_spec;
    ipv4.ttl = ipv4.ttl - 1;
}

@stage(11)
table ipv4_route {
    key = {
        ipv4.dstAddr : exact;
    }
    actions = {
        set_egress;
    }
    size : 8192;
}
