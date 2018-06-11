#define HH_LOAD_WIDTH       32
#define HH_LOAD_NUM         256
#define HH_LOAD_HASH_WIDTH  8
#define HH_THRESHOLD        128
#define HH_BF_NUM           512
#define HH_BF_HASH_WIDTH    9

struct nc_load_md_t {
    bit<16> index;
        
    bit<HH_LOAD_WIDTH> load;
}
nc_load_md_t nc_load_md;

Register<bit<HH_LOAD_WIDTH>>(HH_LOAD_NUM) hh_load_reg

action hh_load_count_act() {
    nc_load_md.index = hash(HashAlgorithm.crc32, 0, {nc_hdr.key}, HH_LOAD_NUM)
    hh_load_reg.read(nc_load_md.load, nc_load_md.index);
    hh_load_reg.write(nc_load_md.index, nc_load_md.load + 1);
}
table hh_load_count {
    actions = {
        hh_load_count_act;
    }
}

control count_min {
    hh_load_count.apply();
}

struct hh_bf_md_t {
    bit<16> index;

    bit<1> bf;
}
hh_bf_md_t hh_bf_md;

Register<bit<1>>(HH_BF_NUM) hh_bf_reg 

action hh_bf_act() {
    hh_bf_md.index = hash(HashAlgorithm.crc32, 0, {nc_hdr.key}, HH_BF_NUM);
    hh_bf_reg.read(hh_bf_md.bf, hh_bf_md.index);
    hh_bf_reg.write(hh_bf_md.index, 1);
}
table hh_bf {
    actions = {
        hh_bf_act;
    }
}

control bloom_filter {
    hh_bf.apply();
}

field_list mirror_list {
    nc_load_md.load_1;
    nc_load_md.load_2;
    nc_load_md.load_3;
    nc_load_md.load_4;
}

#define CONTROLLER_MIRROR_DSET 3
action clone_to_controller_act() {
    clone_egress_pkt_to_egress(CONTROLLER_MIRROR_DSET, mirror_list);
}

table clone_to_controller {
    actions = {
        clone_to_controller_act;
    }
}

control report_hot_step_1 {
    clone_to_controller.apply();
}

#define CONTROLLER_IP 0x0a000003
action report_hot_act() {
    nc_hdr.op = NC_HOT_READ_REQUEST;
    
    add_header (nc_load); //TODO Devon I don't know what this does in modern p4
    ipv4.totalLen = 16;
    udp.len = 16;
    nc_load.load_1 = nc_load_md.load_1;
    nc_load.load_2 = nc_load_md.load_2;
    nc_load.load_3 = nc_load_md.load_3;
    nc_load.load_4 = nc_load_md.load_4;
    
    ipv4.dstAddr = CONTROLLER_IP;
}

table report_hot {
    actions {
        report_hot_act;
    }
}

control report_hot_step_2 {
    apply (report_hot);
}   

control heavy_hitter {
    if (standard_metadata.instance_type == 0) {
        count_min();
        if (nc_load_md.load_1 > HH_THRESHOLD) {
            if (nc_load_md.load_2 > HH_THRESHOLD) {
                if (nc_load_md.load_3 > HH_THRESHOLD) {
                    if (nc_load_md.load_4 > HH_THRESHOLD) {
                        bloom_filter();
                        if (hh_bf_md.bf_1 == 0 or hh_bf_md.bf_2 == 0 or hh_bf_md.bf_3 == 0){
                            report_hot_step_1();
                        }
                    }
                }
            }
        }
    }
    else {
        report_hot_step_2();
    }
}
