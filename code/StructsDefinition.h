//
//  StructsDefinition.h
//  lab
//
//  Created by 张晓天 on 2019/4/25.
//  Copyright © 2019 张晓天. All rights reserved.
//

#ifndef StructsDefinition_h
#define StructsDefinition_h
typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;

typedef struct ip_hdr
{
    int version:4; //version of header
    int header_len:4; //length of header
    u_char tos:8; //type of service
    int total_len:16; //total length of header
    int ident:16; //identyfy
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}ip_hdr;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ac;
    int header_len:4;
    int res:6;
    int URG:1;
    int ACK:1;
    int PSH:1;
    int RST:1;
    int SYN:1;
    int FIN:1;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}tcp_hdr;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
}udp_hdr;

typedef struct arp_hdr
{
    u_short tohrd;
    u_short topro;
    u_char hrd_addr_len;
    u_char pro_addr_len;
    u_short arp_op;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];
}arp_hdr;
#endif /* StructsDefinition_h */
