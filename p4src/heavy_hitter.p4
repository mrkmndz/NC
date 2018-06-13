#define HH_LOAD_WIDTH       32
#define HH_LOAD_NUM         256
#define HH_LOAD_HASH_WIDTH  8
#define HH_THRESHOLD        128
#define HH_BF_NUM           512
#define HH_BF_HASH_WIDTH    9

header_type nc_load_md_t {
    fields {
        index_1: 16;
        
        load_1: 32;
    }
}
metadata nc_load_md_t nc_load_md;

field_list hh_hash_fields {
    nc_hdr.key;
}

register hh_load_1_reg {
    width: HH_LOAD_WIDTH;
    instance_count: HH_LOAD_NUM;
}
field_list_calculation hh_load_1_hash {
    input {
        hh_hash_fields;
    }
    algorithm : crc32;
    output_width : HH_LOAD_HASH_WIDTH;
}
action hh_load_1_count_act() {
    modify_field_with_hash_based_offset(nc_load_md.index_1, 0, hh_load_1_hash, HH_LOAD_NUM);
    register_read(nc_load_md.load_1, hh_load_1_reg, nc_load_md.index_1);
    register_write(hh_load_1_reg, nc_load_md.index_1, nc_load_md.load_1 + 1);
}
table hh_load_1_count {
    actions {
        hh_load_1_count_act;
    }
}

control count_min {
    apply (hh_load_1_count);
}

header_type hh_bf_md_t {
    fields {
        index_1: 16;
    
        bf_1: 1;
    }
}
metadata hh_bf_md_t hh_bf_md;

register hh_bf_1_reg {
    width: 1;
    instance_count: HH_BF_NUM;
}
field_list_calculation hh_bf_1_hash {
    input {
        hh_hash_fields;
    }
    algorithm : crc32;
    output_width : HH_BF_HASH_WIDTH;
}
action hh_bf_1_act() {
    modify_field_with_hash_based_offset(hh_bf_md.index_1, 0, hh_bf_1_hash, HH_BF_NUM);
    register_read(hh_bf_md.bf_1, hh_bf_1_reg, hh_bf_md.index_1);
    register_write(hh_bf_1_reg, hh_bf_md.index_1, 1);
}
table hh_bf_1 {
    actions {
        hh_bf_1_act;
    }
}

control bloom_filter {
    apply (hh_bf_1);
}

#define CONTROLLER_IP 0x0a000003
action report_hot_act() {
    modify_field (ipv4.dstAddr, CONTROLLER_IP);
    modify_field (udp.checksum, 0);
}

table report_hot {
    actions {
        report_hot_act;
    }
}

control report_hot_ctrl {
    apply (report_hot);
}   

control heavy_hitter {
        count_min();
        if (nc_load_md.load_1 > HH_THRESHOLD) {
            bloom_filter();
            if (hh_bf_md.bf_1 == 0){
                report_hot_ctrl();
            }
        }
}
