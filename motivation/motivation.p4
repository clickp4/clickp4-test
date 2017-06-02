// 1 manage traffic
// 2 data traffic
#define FLOW 2
#define FLOW_OPT 1

header_type intrinsic_metadata_t {
	fields {
        ingress_global_timestamp : 48;
        lf_field_list : 8;
        mcast_grp : 16;
        egress_rid : 16;
        resubmit_flag : 8;
        recirculate_flag : 8;
	}
}

metadata intrinsic_metadata_t intrinsic_metadata;

header_type qos_metadata_t {
    fields {
        priority : 8;
    }
} 

metadata qos_metadata_t qos_metadata;

#define ETH_TYPE_VLAN         0x8100
#define ETH_TYPE_IPv4         0x0800
#define ETH_TYPE_IPv6         0x86dd


header_type ethernet_t {
    fields {
        dst_addr : 48;
        src_addr : 48;
        eth_type : 16;
    }
}

header ethernet_t ethernet;

#define IP_PROTO_ICMP              1
#define IP_PROTO_TCP               6
#define IP_PROTO_UDP               17

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        total_len : 16;
        identification : 16;
        flags : 3;
        frag_offset : 13;
        ttl : 8;
        proto : 8;
        checksum : 16;
        src_addr : 32;
        dst_addr: 32;
    }
}

header ipv4_t ipv4;

header_type tcp_t {
    fields {
        src_port : 16;
        dst_port : 16;
        seq_no : 32;
        ack_no : 32;
        data_offset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgent_ptr : 16;
    }
}

header tcp_t tcp;

header_type udp_t {
    fields {
        src_port : 16;
        dst_port : 16;
        length_ : 16;
        checksum : 16;
    }
}

header udp_t udp;

header_type vlan_t {
    fields {
        pcp : 3;
        cfi : 1;
        vfi : 12;
        eth_type : 16;
    }
}

header vlan_t vlan;

header_type icmp_t {
    fields {
        type_ : 8;
        code : 8;
        checksum : 16;
    }
}

header icmp_t icmp;


header_type ipv6_t {
    fields {
        version : 4;
        traffic_class : 8;
        flow_label : 20;
        payload_len : 16;
        next_hdr : 8;
        hop_limit : 8;
        src_addr : 128;
        dst_addr : 128;
    }
}

header ipv6_t ipv6;


parser parse_ipv6 {
    extract(ipv6);
    return select(ipv6.next_hdr) {
        IP_PROTO_TCP : parse_tcp;
        IP_PROTO_UDP : parse_udp;
        default : ingress;
    }
}


parser start {
    return parse_ethernet;
}

parser parse_icmp {
	extract(icmp);
	return ingress;
}

parser parse_vlan {
    extract(vlan);
    return select(vlan.eth_type) {
        ETH_TYPE_IPv4 : parse_ipv4;
        ETH_TYPE_IPv6 : parse_ipv6;
        default : ingress;
    }
}

parser parse_udp {
    extract(udp);
    return ingress;
}


parser parse_tcp {
    extract(tcp);
    return ingress;
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.proto) {
    IP_PROTO_TCP : parse_tcp;
    IP_PROTO_UDP : parse_udp;
    IP_PROTO_ICMP : parse_icmp;

    default : ingress;
    }
}

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.eth_type) {
        ETH_TYPE_IPv4 : parse_ipv4;
        ETH_TYPE_IPv6 : parse_ipv6;
        ETH_TYPE_VLAN : parse_vlan;
        default : ingress;
    }
}

action nop() {
    
}

action block() {
    drop();
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

field_list mac_learn_digest {
	standard_metadata.ingress_port;
    ethernet.src_addr;
}

action mac_learn(receiver) {
    generate_digest(receiver, mac_learn_digest);
}

table smac {
    reads {
        ethernet.src_addr : exact;
    }
    actions {
        nop;
        mac_learn;
    }
    size : 1024;
}

table dmac {
    reads {
        ethernet.dst_addr : exact;
    }
    actions {
    	forward;
    }
    size : 1024;
}

control l2_switch {
    apply(smac);
    apply(dmac);
}




table firewall {
    reads {
        ipv4.src_addr : ternary;
        ipv4.dst_addr : ternary;
        ipv6.src_addr : ternary;
        ipv6.dst_addr : ternary;
        tcp.src_port  : ternary;
        tcp.dst_port  : ternary;
        udp.src_port  : ternary;
        udp.dst_port  : ternary;
    }
    actions {
        block;
        nop;
    }
    size : 1024;
}

control firewall {
    apply(firewall);
}

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.total_len;
        ipv4.identification;
        ipv4.flags;
        ipv4.frag_offset;
        ipv4.ttl;
        ipv4.proto;
        ipv4.src_addr;
        ipv4.dst_addr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.checksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

header_type l3_switch_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}
metadata l3_switch_metadata_t l3_switch_metadata;

action set_nhop(nhop_ipv4) {
    modify_field(l3_switch_metadata.nhop_ipv4, nhop_ipv4);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_nhop {
    reads {
        ipv4.dst_addr : lpm;
    }
    actions {
        set_nhop;
        block;
    }
    size: 1024;
}

action set_dmac(dmac, port) {
    modify_field(ethernet.dst_addr, dmac);
    forward(port);
}

table forward_table {
    reads {
        l3_switch_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
    }
    size: 1024;
}

action set_smac(smac) {
    modify_field(ethernet.src_addr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_spec: exact;
    }
    actions {
        set_smac;
        block;
    }
    size: 1024;
}

control l3_switch {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_nhop);
        apply(forward_table);
        apply(send_frame);
    }
}

action set_priority(p) {
    modify_field(qos_metadata.priority, p);
}
table qos {
    reads {
        ipv4.src_addr : ternary;
        ipv4.dst_addr : ternary;
        ipv4.proto    : ternary;
        tcp.src_port  : ternary;
        tcp.dst_port  : ternary;
        udp.src_port  : ternary;
        udp.dst_port  : ternary;
    }
    actions {
        nop;
        set_priority;
    }
    size : 1024;
}

control qos {
    apply(qos);
}

action vlan_decap() {
	modify_field(ethernet.eth_type, vlan.eth_type);
	remove_header(vlan);
}

action vlan_encap(pcp, cfi, vfi) {
	add_header(vlan);
	modify_field(vlan.eth_type, ethernet.eth_type);
	modify_field(vlan.cfi, cfi);
	modify_field(vlan.pcp, pcp);
	modify_field(vlan.vfi, vfi);
	modify_field(ethernet.eth_type, ETH_TYPE_VLAN);
}

action on_miss() {

}

table port_domain {
	reads {
		standard_metadata.egress_spec : exact;
	}
	actions {
		nop;
        on_miss;
	}
}

table vlan_filter{
	reads {
		vlan.vfi : exact;
		standard_metadata.egress_spec : exact;
	}
	actions {
		block;
		vlan_decap;
	}
}

table vlan {
	reads {
		ethernet.src_addr  : exact;
	}
	actions {
		vlan_encap;
        on_miss;
	}	
	
}

control vlan {
	apply(vlan) {
		on_miss {
			apply(port_domain) {
				on_miss {
					apply(vlan_filter);
				}
			}
		}
	}
}

#if FLOW == 1
control ingress {
    l2_switch();
#if FLOW_OPT != 1
    vlan();
    firewall();
#endif
    qos();
}
#else 

control ingress {
#if FLOW_OPT != 1
    l2_switch();
#endif
    l3_switch();
    firewall();
#if FLOW_OPT != 1
    qos();
#endif

}
#endif