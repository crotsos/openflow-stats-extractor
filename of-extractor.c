#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <libhashish.h>

#include "openflow/openflow.h"
#include "storage.h"
#include "ofpbuf.h"
#include "flow.h"
#include "packets.h"

enum capture_type {
  FILE_CAPTURE,
  DEVICE_CAPTURE,
  MAX_CAPTURE_TYPE,
};

#define CLEANUP_TIMEOUT 10
#define CONNECTION_TIMEOUT 10

struct str_cfg {
  int verbose;
  int type;
  char filename[1000];
  char dev_name[1000];
  char pcap_filter[1000];
  pcap_t * pcap_dev;

  char target[100];
  unsigned short port;

  ///a hast structure to store state
  hi_handle_t *hi_handle_ip; 
  hi_handle_t *hi_handle_flows;

};

struct str_cfg obj_cfg;

#define ETHER_ADDR_SIZE 6
#define SIZE_ETHERNET 14

struct packet_header {
  struct ether_header *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  struct tcphdr *tcp;
};

#define USAGE "./of-extractor [-i device -f file -v]"


/*
 * A function to fill in a packet_header structure from a captured file
 * return 0 in case of problem during decompression.
 */
/* /\* int  *\/ */
/* /\* extract_headers( struct flow *flow, struct ofpbuf *packet, int data_len) { *\/ */

/* /\*   struct ofpbuf b = *packet; *\/ */
/* /\*   struct eth_header *eth; *\/ */
/* /\*   int retval = 0; *\/ */

/* /\*   memset(flow, 0, sizeof *flow); *\/ */
/* /\*   flow->dl_vlan = htons(OFP_VLAN_NONE); *\/ */
/* /\*   flow->in_port = htons(1); *\/ */
  
/* /\*   packet->l2 = b.data; *\/ */
/* /\*   packet->l3 = NULL; *\/ */
/* /\*   packet->l4 = NULL; *\/ */
/* /\*   packet->l7 = NULL; *\/ */
  
/* /\*   eth = pull_eth(&b); *\/ */
/* /\*   if (eth) { *\/ */
/* /\*     if (ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF) { *\/ */
/* /\*       /\\* This is an Ethernet II frame *\\/ *\/ */
/* /\*       flow->dl_type = eth->eth_type; *\/ */
/* /\*     } else { *\/ */
/* /\*       /\\* This is an 802.2 frame *\\/ *\/ */
/* /\*             struct llc_header *llc = ofpbuf_at(&b, 0, sizeof *llc); *\/ */
/* /\*             struct snap_header  *snap = ofpbuf_at(&b, sizeof *llc, *\/ */
/* /\*                                                  sizeof *snap); *\/ */
/* /\*             if (llc == NULL) { *\/ */
/* /\*                 return 0; *\/ */
/* /\*             } *\/ */
/* /\*             if (snap *\/ */
/* /\*                 && llc->llc_dsap == LLC_DSAP_SNAP *\/ */
/* /\*                 && llc->llc_ssap == LLC_SSAP_SNAP *\/ */
/* /\*                 && llc->llc_cntl == LLC_CNTL_SNAP *\/ */
/* /\*                 && !memcmp(snap->snap_org, SNAP_ORG_ETHERNET, *\/ */
/* /\*                            sizeof snap->snap_org)) { *\/ */
/* /\*                 flow->dl_type = snap->snap_type; *\/ */
/* /\*                 ofpbuf_pull(&b, LLC_SNAP_HEADER_LEN); *\/ */
/* /\*             } else { *\/ */
/* /\*                 flow->dl_type = htons(OFP_DL_TYPE_NOT_ETH_TYPE); *\/ */
/* /\*                 ofpbuf_pull(&b, sizeof(struct llc_header)); *\/ */
/* /\*             } *\/ */
/* /\*         } *\/ */

/* /\*         /\\* Check for a VLAN tag *\\/ *\/ */
/* /\*         if (flow->dl_type == htons(ETH_TYPE_VLAN)) { *\/ */
/* /\*             struct vlan_header *vh = pull_vlan(&b); *\/ */
/* /\*             if (vh) { *\/ */
/* /\*                 flow->dl_type = vh->vlan_next_type; *\/ */
/* /\*                 flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK); *\/ */
/* /\*                 flow->dl_vlan_pcp = (uint8_t)((ntohs(vh->vlan_tci) >> VLAN_PCP_SHIFT) *\/ */
/* /\*                                                & VLAN_PCP_BITMASK); *\/ */
/* /\*             } *\/ */
/* /\*         } *\/ */
/* /\*         memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN); *\/ */
/* /\*         memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN); *\/ */

/* /\*         packet->l3 = b.data; *\/ */
/* /\*         if (flow->dl_type == htons(ETH_TYPE_IP)) { *\/ */
/* /\*             const struct ip_header *nh = pull_ip(&b); *\/ */
/* /\*             if (nh) { *\/ */
/* /\*                 flow->nw_tos = nh->ip_tos & 0xfc; *\/ */
/* /\*                 flow->nw_proto = nh->ip_proto; *\/ */
/* /\*                 flow->nw_src = nh->ip_src; *\/ */
/* /\*                 flow->nw_dst = nh->ip_dst; *\/ */
/* /\*                 packet->l4 = b.data; *\/ */
/* /\*                 if (!IP_IS_FRAGMENT(nh->ip_frag_off)) { *\/ */
/* /\*                     if (flow->nw_proto == IP_TYPE_TCP) { *\/ */
/* /\*                         const struct tcp_header *tcp = pull_tcp(&b); *\/ */
/* /\*                         if (tcp) { *\/ */
/* /\*                             flow->tp_src = tcp->tcp_src; *\/ */
/* /\*                             flow->tp_dst = tcp->tcp_dst; *\/ */
/* /\*                             packet->l7 = b.data; *\/ */
/* /\*                         } else { *\/ */
/* /\*                             /\\* Avoid tricking other code into thinking that *\/ */
/* /\*                              * this packet has an L4 header. *\\/ *\/ */
/* /\*                             flow->nw_proto = 0; *\/ */
/* /\*                         } *\/ */
/* /\*                     } else if (flow->nw_proto == IP_TYPE_UDP) { *\/ */
/* /\*                         const struct udp_header *udp = pull_udp(&b); *\/ */
/* /\*                         if (udp) { *\/ */
/* /\*                             flow->tp_src = udp->udp_src; *\/ */
/* /\*                             flow->tp_dst = udp->udp_dst; *\/ */
/* /\*                             packet->l7 = b.data; *\/ */
/* /\*                         } else { *\/ */
/* /\*                             /\\* Avoid tricking other code into thinking that *\/ */
/* /\*                              * this packet has an L4 header. *\\/ *\/ */
/* /\*                             flow->nw_proto = 0; *\/ */
/* /\*                         } *\/ */
/* /\*                     } else if (flow->nw_proto == IP_TYPE_ICMP) { *\/ */
/* /\*                         const struct icmp_header *icmp = pull_icmp(&b); *\/ */
/* /\*                         if (icmp) { *\/ */
/* /\*                             flow->icmp_type = htons(icmp->icmp_type); *\/ */
/* /\*                             flow->icmp_code = htons(icmp->icmp_code); *\/ */
/* /\*                             packet->l7 = b.data; *\/ */
/* /\*                         } else { *\/ */
/* /\*                             /\\* Avoid tricking other code into thinking that *\/ */
/* /\*                              * this packet has an L4 header. *\\/ *\/ */
/* /\*                             flow->nw_proto = 0; *\/ */
/* /\*                         } *\/ */
/* /\*                     } *\/ */
/* /\*                 } else { *\/ */
/* /\*                     retval = 1; *\/ */
/* /\*                 } *\/ */
/* /\*             } *\/ */
/* /\*         } else if (flow->dl_type == htons(ETH_TYPE_ARP)) { *\/ */
/* /\*             const struct arp_eth_header *arp = pull_arp(&b); *\/ */
/* /\*             if (arp) { *\/ */
/* /\*                 if (arp->ar_pro == htons(ARP_PRO_IP) && arp->ar_pln == IP_ADDR_LEN) { *\/ */
/* /\*                     flow->nw_src = arp->ar_spa; *\/ */
/* /\*                     flow->nw_dst = arp->ar_tpa; *\/ */
/* /\*                 } *\/ */
/* /\*                 flow->nw_proto = ntohs(arp->ar_op) & 0xff; *\/ */
/* /\*             } *\/ */
/* /\*         } *\/ */
/* /\*     } *\/ */
/* /\*     return retval; *\/ */

/*   /\* int ptr = 0; *\/ */
/*   /\* struct ether_header *ether;  *\/ */

/*   /\* //extract ethernet header *\/ */
/*   /\* if(data_len < ETHER_HDR_LEN) return 0; *\/ */
/*   /\* ether = (struct ether_header *)data; *\/ */
/*   /\* memcpy(match->dl_src, ether->ether_shost, ETH_ALEN); *\/ */
/*   /\* memcpy(match->dl_dst, ether->ether_dhost, ETH_ALEN); *\/ */

/*   /\* if(ether->ether_type == ETHERTYPE_IP) { *\/ */
/*   /\*   match->dl_vlan = 0xffff; *\/ */
/*   /\*   match->dl_vlan_pcp = 0; *\/ */
/*   /\*   match->dl_type = ETHERTYPE_IP; *\/ */
/*   /\* } else if ( match->ETHERTYPE_VLAN ) { *\/ */
/*   /\* } else if (ETHERTYPE_ARP) { *\/ */
    
/*   /\* } *\/ */

/*   /\* ptr += ETHER_HDR_LEN; *\/ */

/*   /\* if(ntohs(hdr->ether->ether_type) != ETHERTYPE_IP) return 0; *\/ */

/*   /\* //extract ip headers *\/ */
/*   /\* if(data_len < ptr + sizeof(struct iphdr)) return 0; *\/ */
/*   /\* hdr->ip = (struct iphdr *)(data + ptr); *\/ */
/*   /\* if(data_len < ptr + (hdr->ip->ihl)*4) return 0;   *\/ */
/*   /\* ptr += hdr->ip->ihl*4; *\/ */

/*   /\* //extract tcp/udp header *\/ */
/*   /\* if(hdr->ip->protocol == 6) { //TCP packet *\/ */
/*   /\*   if(data_len < ptr + sizeof(struct tcphdr)) return 0; *\/ */
/*   /\*   hdr->tcp = (struct tcphdr *)(data + ptr); *\/ */
    
/*   /\* } else if(hdr->ip->protocol == 17) { //UDP packet *\/ */
/*   /\*   if(data_len < ptr + sizeof(struct udphdr)) return 0; *\/ */
/*   /\*   hdr->udp = (struct udphdr *)(data + ptr); *\/ */
/*   /\* } else  *\/ */
/*   /\*   return 0; *\/ */
/*   /\* return 1; *\/ */
//}

/* static void  */
/* *get_id(const uint8_t* ip) { */
/*   uint32_t i, res; */
/*   char str_ip[20]; */
/*   struct in_addr addr; */
/*   struct osdpi_id *data; */

/*   addr.s_addr = ip; */

/*   sprintf(str_ip, "%s", inet_ntoa(addr)); */
/*   res = hi_get_str(obj_cfg.hi_handle_ip, str_ip, (void *)&data); */

/*   //if state found retrurn object */
/*   if(res == HI_ERR_SUCCESS) { */
/*     return data->ipoque_id; */
/*   } else { */
/*     //if file not found create new state */
/*     data = malloc(sizeof(struct osdpi_id)); */
/*     if(data == NULL) { */
/*       perror("malloc osdpi_id"); */
/*       exit(1); */
/*     } */
/*     memcpy(data->ip, ip, 4); */
/*     data->ipoque_id = calloc(1, ipoque_detection_get_sizeof_ipoque_id_struct()); */
/*     if(data->ipoque_id == NULL) { */
/*       perror("malloc osdpi_id->ipoque_id"); */
/*       exit(1); */
/*     } */
/*     hi_insert_str(obj_cfg.hi_handle_ip, str_ip, data); */
/*     return  data->ipoque_id; */
/*   } */
/* } */

/* void */
/* garbadge_collect_osdpi_flows(uint32_t time ) { */
/*   hi_iterator_t *iter; */
/*   struct osdpi_flow *data; */
/*   char *key; */
/*   uint32_t len; */
/*   int res; */

/*   printf("hash elements: %lu\n", hi_no_objects(obj_cfg.hi_handle_flows)); */

/*   if( (res = hi_iterator_create(obj_cfg.hi_handle_flows, &iter)) != HI_SUCCESS) { */
/*     printf("Failed to init iterator: %s(%d)\n", hi_strerror(res), res); */
/*     return; */
/*   } */

/*   while(hi_iterator_getnext(iter, (void **)&data, (void **)&key, &len) == HI_SUCCESS ) { */
/*     if( time - data->last_pkt > CONNECTION_TIMEOUT) { */
/*       printf(">>>>>>>>> flow %s %d : %d %d %d %ld\n", key, len, data->byte_count, data->pkt_count, data->last_pkt); */
/*       hi_remove_str(obj_cfg.hi_handle_flows, key, &data); */
/*       free(data->ipoque_flow); */
/*       free(data); */
/*       //      printf("flow timed out\n"); */
/*     } else { */
/*       printf("flow %s %d : %lu %lu %lu\n", key, len, data->byte_count, data->pkt_count, data->last_pkt); */
/*     } */
/*   } */

/*    hi_iterator_fini(iter); */
/* } */

void 
process_packet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* data) {
  struct packet_header hdr;
  char src_ip[20], dst_ip[20];
  struct in_addr addr;
  struct flow flow;

  struct ofpbuf *packet  = NULL;

  packet = ofpbuf_new(pkthdr->caplen);
  if (packet == NULL) {
    perror("ofpbuf_new");
    exit(1);
  } else {
    //buffer->data = (char*)buffer->data + headroom;
    packet->size = pkthdr->caplen;
    memcpy(packet->data, data, pkthdr->caplen);
  }

  if(flow_extract(packet, 1, &flow))  { 
    return; 
  } 
  
  flow_print(stdin, &flow);

  printf("port %04x vlan-vid %04x vlan-pcp %02x src-mac "
  	 ETH_ADDR_FMT" dst-mac "ETH_ADDR_FMT" frm-type %04x "
  	 "ip-tos %02x ip-proto %02x src-ip "IP_FMT" dst-ip "
  	 IP_FMT" tp-src %d tp-dst %d\n",
  	 ntohs(flow.in_port), ntohs(flow.dl_vlan),
  	 flow.dl_vlan_pcp, ETH_ADDR_ARGS(flow.dl_src),
  	 ETH_ADDR_ARGS(flow.dl_dst), ntohs(flow.dl_type),
  	 flow.nw_tos, flow.nw_proto, IP_ARGS(&flow.nw_src),
  	 IP_ARGS(&flow.nw_dst), ntohs(flow.tp_src),
  	 ntohs(flow.tp_dst));

  
  ofpbuf_delete(packet);

  return;

  addr.s_addr=hdr.ip->saddr;
  strcpy(src_ip, (char *)inet_ntoa(addr));
  addr.s_addr=hdr.ip->daddr;
  strcpy(dst_ip, (char *)inet_ntoa(addr));

  //src = get_id((uint8_t *) & hdr.ip->saddr);
  //dst = get_id((uint8_t *) & hdr.ip->daddr);

  if ((hdr.ip->frag_off & htons(0x1FFF)) == 0) {
    uint64_t time =((((uint64_t) pkthdr->ts.tv_sec)*1000) + pkthdr->ts.tv_usec/1000);
    
  } else {
    static uint8_t frag_warning_used = 0;
    if (frag_warning_used == 0) {
      printf("\n\nWARNING: fragmented ip packets are not supported "
	     "and will be skipped \n\n");
      sleep(2);
      frag_warning_used = 1;
    }
    return;
  }
}


/*
 * Initialize the configuration structure
 */
void
init_cfg() {
  int res;

  obj_cfg.verbose = 0;
  obj_cfg.type = DEVICE_CAPTURE;
  strcpy(obj_cfg.dev_name, "eth0");
  strcpy(obj_cfg.pcap_filter, "udp or tcp");

  /* hi_init_str(&obj_cfg.hi_handle_ip, 93563); */

  /* if( (res = hi_init_str(&obj_cfg.hi_handle_flows, 93563)) != HI_SUCCESS) { */
  /*   printf("Failed to init flow_hasr: %s\n", hi_strerror(res)); */
  /*   exit(1); */
  /* } */

};


/*
 * Parse the command line parameters and modify appropriately the config object
 */
int 
parse_options(int argc, char *argv[]) {
  int i, j, c;
  //intiliaze program configuration object
  init_cfg();

  while ((c = getopt (argc, argv, "f:r:i:v")) != -1) {
    switch (c) {
    case 'f':
      strcpy(obj_cfg.pcap_filter, optarg);
      break;
    case 'r':
      strcpy(obj_cfg.filename, optarg);
      obj_cfg.type = FILE_CAPTURE;
      break;
    case 'i':
      strcpy(obj_cfg.dev_name, optarg);
      obj_cfg.type = DEVICE_CAPTURE;
      break;
    case 'v':
      obj_cfg.verbose = 1;
      break;
    case 'h':
      printf("usage: %s\n", USAGE);
      exit(0);
    default:
      printf("unknown param -%c. \n usage: %s\n", c, USAGE);
      exit(0);
    } 
  }
}


/*
 * Initialize pcap structures and rpc structures
 */
int
init() {  
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;      /* hold compiled program     */
  uint32_t size_id_struct; 
  uint32_t size_flow_struct;
  uint32_t i;
  static uint64_t dpid = UINT64_MAX;

  /* ask pcap for the network address and mask of the device */
  if(obj_cfg.type == DEVICE_CAPTURE) {
    if (obj_cfg.verbose) 
      printf("Device is %s\n", obj_cfg.dev_name);
    //pcap_lookupnet(dev, &netp, &maskp, errbuf);
    
    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    obj_cfg.pcap_dev = pcap_open_live(obj_cfg.dev_name, BUFSIZ, 
				      1, -1, errbuf);
    if(obj_cfg.pcap_dev == NULL) {
      fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
      exit(1);
    }
  } else if (obj_cfg.type == FILE_CAPTURE) {
    if (obj_cfg.verbose) 
      printf("File is %s\n", obj_cfg.filename);
    obj_cfg.pcap_dev = pcap_open_offline(obj_cfg.filename, errbuf);
    if(obj_cfg.pcap_dev == NULL) {
      fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
      exit(1);
    }
  } else {
      fprintf(stderr, "No device or file was defined for "
	      "capturing\n");
      exit(1);
  }

  if(strlen(obj_cfg.pcap_filter) > 0) {
    /* Lets try and compile the program.. non-optimized */
    if(pcap_compile(obj_cfg.pcap_dev, &fp, obj_cfg.pcap_filter, 0, 0) == -1) {
      fprintf(stderr, "Error calling pcap_compile: $%s %s\n", 
	      obj_cfg.pcap_filter, pcap_geterr(obj_cfg.pcap_dev));
      exit(1);
    }
    
    /* set the compiled program as the filter */
    if(pcap_setfilter(obj_cfg.pcap_dev, &fp) == -1) {
      fprintf(stderr, "Error setting filter\n");
      exit(1);
    }
  }
  
  //Initialize the datapath structure to store packets
  //error = dp_new(&dp, dpid);
}

int
main(int argc, char *argv[]) {	
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 maskp;
  bpf_u_int32 netp;
  u_char* args = NULL;
  pthread_t thr;
  int i;
  char buf[100];

  // Initialize link accumulator.
  //  lt_init();
  parse_options(argc, argv);
  init();

  // and the thread that processes (inserts into hwdb) the accumulated results.
/*   if (pthread_create(&thr, NULL, handler, NULL)) { */
/*     fprintf(stderr, "Failure to start database thread\n"); */
/*     exit(1); */
/*   } */
  /* ... and loop */ 
  pcap_loop(obj_cfg.pcap_dev, -1, process_packet, args);
  fprintf(stderr, "\nfinished\n");
  pcap_close(obj_cfg.pcap_dev);

  return 0;
}
