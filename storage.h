#ifndef STORAGE_H_

#define STORAGE_H_ 1

/* Identification data for a flow.
   All fields are in network byte order.
   In decreasing order by size, so that flow structures can be hashed or
   compared bytewise. */
/* struct flow { */
/*     uint32_t nw_src;            /\* IP source address. *\/ */
/*     uint32_t nw_dst;            /\* IP destination address. *\/ */
/*     uint16_t in_port;           /\* Input switch port. *\/ */
/*     uint16_t dl_vlan;           /\* Input VLAN id. *\/ */
/*     uint16_t dl_type;           /\* Ethernet frame type. *\/ */
/*     uint16_t tp_src;            /\* TCP/UDP source port. *\/ */
/*     uint16_t tp_dst;            /\* TCP/UDP destination port. *\/ */
/*     uint8_t dl_src[6];          /\* Ethernet source address. *\/ */
/*     uint8_t dl_dst[6];          /\* Ethernet destination address. *\/ */
/*     uint8_t dl_vlan_pcp;        /\* Input VLAN priority. *\/ */
/*     uint8_t nw_tos;             /\* IPv4 DSCP. *\/ */
/*     uint8_t nw_proto;           /\* IP protocol. *\/ */
/*     uint8_t pad[3]; */
/* }; */

#endif
