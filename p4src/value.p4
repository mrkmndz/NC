#define REGISTER_VALUE_SLICE(i, j) \
    Register<bit<32>>(NUM_CACHE) value_##i##_##j##_reg;

#define REGISTER_VALUE(i) \
    REGISTER_VALUE_SLICE(i, 1) \
    REGISTER_VALUE_SLICE(i, 2) \
    REGISTER_VALUE_SLICE(i, 3) \
    REGISTER_VALUE_SLICE(i, 4) 

#define ACTION_READ_VALUE_SLICE(i, j) \
    action read_value_##i##_##j##_act() { \
        value_##i##_##j##_reg.read(nc_value_##i.value_##i##_##j,  nc_cache_md.cache_index); \
    }

#define ACTION_READ_VALUE(i) \
    ACTION_READ_VALUE_SLICE(i, 1) \
    ACTION_READ_VALUE_SLICE(i, 2) \
    ACTION_READ_VALUE_SLICE(i, 3) \
    ACTION_READ_VALUE_SLICE(i, 4)

#define TABLE_READ_VALUE_SLICE(i, j) \
    table read_value_##i##_##j { \
        actions = { \
            read_value_##i##_##j##_act; \
        } \
        default_action = read_value_##i##_##j##_act; \
    }

#define TABLE_READ_VALUE(i) \
    TABLE_READ_VALUE_SLICE(i, 1) \
    TABLE_READ_VALUE_SLICE(i, 2) \
    TABLE_READ_VALUE_SLICE(i, 3) \
    TABLE_READ_VALUE_SLICE(i, 4)

#define ACTION_ADD_VALUE_HEADER(i) \
    action add_value_header_##i##_act() { \
        ipv4.totalLen = ipv4.totalLen + 16;\
        udp.totalLen = udp.totalLen + 16;\
        nc_value_##i.setValid(True); \
    }

#define TABLE_ADD_VALUE_HEADER(i) \
    table add_value_header_##i { \
        actions = { \
            add_value_header_##i##_act; \
        } \
        default_action = add_value_header_##i##_act; \
    }

#define ACTION_WRITE_VALUE_SLICE(i, j) \
    action write_value_##i##_##j##_act() { \
      value_##i##_##j##_reg.write(nc_cache_md.cache_index, nc_value_##i.value_##i##_##j); \
    }

#define ACTION_WRITE_VALUE(i) \
    ACTION_WRITE_VALUE_SLICE(i, 1) \
    ACTION_WRITE_VALUE_SLICE(i, 2) \
    ACTION_WRITE_VALUE_SLICE(i, 3) \
    ACTION_WRITE_VALUE_SLICE(i, 4)

#define TABLE_WRITE_VALUE_SLICE(i, j) \
    table write_value_##i##_##j { \
        actions = { \
            write_value_##i##_##j##_act; \
        } \
        default_action = write_value_##i##_##j##_act; \
    }

#define TABLE_WRITE_VALUE(i) \
    TABLE_WRITE_VALUE_SLICE(i, 1) \
    TABLE_WRITE_VALUE_SLICE(i, 2) \
    TABLE_WRITE_VALUE_SLICE(i, 3) \
    TABLE_WRITE_VALUE_SLICE(i, 4)

#define ACTION_REMOVE_VALUE_HEADER(i) \
    action remove_value_header_##i##_act() { \
        ipv4.totalLen = ipv4.totalLen - 16;\
        udp.totalLen = udp.totalLen - 16;\
        nc_value_##i.setValid(false); \
    }

#define TABLE_REMOVE_VALUE_HEADER(i) \
    table remove_value_header_##i { \
        actions = { \
            remove_value_header_##i##_act; \
        } \
        default_action = remove_value_header_##i##_act; \
    }

#define CONTROL_PROCESS_VALUE(i) \
    control process_value_##i { \
        if (nc_hdr.op == NC_READ_REQUEST and nc_cache_md.cache_valid == 1) { \
            add_value_header_##i.apply(); \
            read_value_##i##_1.apply(); \
            read_value_##i##_2.apply(); \
            read_value_##i##_3.apply(); \
            read_value_##i##_4.apply(); \
        } \
        else if (nc_hdr.op == NC_UPDATE_REPLY and nc_cache_md.cache_exist == 1) { \
            write_value_##i##_1.apply(); \
            write_value_##i##_2.apply(); \
            write_value_##i##_3.apply(); \
            write_value_##i##_4.apply(); \
            remove_value_header_##i.apply(); \
        } \
    }

#define HANDLE_VALUE(i) \
    REGISTER_VALUE(i) \
    ACTION_READ_VALUE(i) \
    TABLE_READ_VALUE(i) \
    ACTION_ADD_VALUE_HEADER(i) \
    TABLE_ADD_VALUE_HEADER(i) \
    ACTION_WRITE_VALUE(i) \
    TABLE_WRITE_VALUE(i) \
    ACTION_REMOVE_VALUE_HEADER(i) \
    TABLE_REMOVE_VALUE_HEADER(i) \
    CONTROL_PROCESS_VALUE(i)

HANDLE_VALUE(1)
HANDLE_VALUE(2)
HANDLE_VALUE(3)
HANDLE_VALUE(4)
HANDLE_VALUE(5)
HANDLE_VALUE(6)
HANDLE_VALUE(7)
HANDLE_VALUE(8)

struct reply_read_hit_info_md_t {
    bit<32> ipv4_srcAddr;
    bit<32> ipv4_dstAddr;
}

reply_read_hit_info_md_t reply_read_hit_info_md;

action reply_read_hit_before_act() {
    reply_read_hit_info_md.ipv4_srcAddr = ipv4.srcAddr;
    reply_read_hit_info_md.ipv4_dstAddr = ipv4.dstAddr;
}

table reply_read_hit_before {
    actions = {
        reply_read_hit_before_act;
    }
    default_action = reply_read_hit_before_act;
}

action reply_read_hit_after_act() {
    ipv4.srcAddr = reply_read_hit_info_md.ipv4_dstAddr;
    ipv4.dstAddr = reply_read_hit_info_md.ipv4_srcAddr;
    nc_hdr.op = NC_READ_REPLY;
}

table reply_read_hit_after {
    actions = {
        reply_read_hit_after_act;
    }
    default_action = reply_read_hit_after_act;
}

control process_value {    
    if (nc_hdr.op == NC_READ_REQUEST and nc_cache_md.cache_valid == 1) {
        reply_read_hit_before.apply();
    }
    process_value_1();
    process_value_2();
    process_value_3();
    process_value_4();
    process_value_5();
    process_value_6();
    process_value_7();
    process_value_8();
    if (nc_hdr.op == NC_READ_REQUEST and nc_cache_md.cache_valid == 1) {
        reply_read_hit_after.apply();
    }
}
