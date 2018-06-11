struct nc_cache_md_t {
        bit<1> cache_exist;
        bit<14> cache_index;
        bit<1> cache_valid;
}


nc_cache_md_t nc_cache_md;


action check_cache_exist_act(index) {
    nc_cache_md.cache_exist = 1;
    nc_cache_md.cache_index = index;
}


table check_cache_exist {
    key = {
        nc_hdr.key: exact;
    }
    actions = {
        check_cache_exist_act;
    }
    size: NUM_CACHE;
}


Register<bit<1>>(NUM_CACHE) cache_valid_reg;

action check_cache_valid_act() {
    cache_valid_reg.read(nc_cache_md.cache_valid, nc_cache_md.cache_index);
}
table check_cache_valid {
    actions = {
        check_cache_valid_act;
    }
    default_action = check_cache_valid_act;
}

action set_cache_valid_act() {
    cache_valid_reg.write(nc_cache_md.cache_index, 1);
}
table set_cache_valid {
    actions = {
        set_cache_valid_act;
    }
    default_action = set_cache_valid_act;
}

control process_cache {
    check_cache_exist.apply();
    if (nc_cache_md.cache_exist == 1) {
        if (nc_hdr.op == NC_READ_REQUEST) {
            check_cache_valid.apply();
        }
        else if (nc_hdr.op == NC_UPDATE_REPLY) {
            set_cache_valid.apply();
        }
    }
}
