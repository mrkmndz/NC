action ethernet_set_mac_act (smac, dmac) {
    ethernet.srcAddr = smac;
    ethernet.dstAddr = dmac;
}

table ethernet_set_mac {
    key = {
        standard_metadata.egress_port: exact;
    }
    actions = {
        ethernet_set_mac_act;
    }
}