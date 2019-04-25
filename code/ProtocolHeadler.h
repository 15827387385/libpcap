//
//  ProtocolHeadler.h
//  lab
//
//  Created by 张晓天 on 2019/4/25.
//  Copyright © 2019 张晓天. All rights reserved.
//

#ifndef ProtocolHeadler_h
#define ProtocolHeadler_h
#include "StructsDefinition.h"
//处理初始数据包
void handlePackage(const struct pcap_pkthdr *packet_header,const unsigned char *packet_content)
{
    printf("基本包信息:\n");
    printf(" 数据包长度: %d\n",packet_header->len);
    printf(" 字节数: %d\n",packet_header->caplen);
    printf(" 接收时间: %s",ctime((const time_t*)&packet_header->ts.tv_sec));
    int i;
    printf(" 数据包内容:\n");
    for(i=0;i<packet_header->caplen;i++){
        printf(" %02x",packet_content[i]);
        if((i+1)%16==0){
            printf("\n");
        }
    }
    printf("\n\n");
}

//处理ethernet包
void handleEtherPackage(eth_hdr *eth)
{
    printf("    源MAC地址  : %02x-%02x-%02x-%02x-%02x-%02x\n",eth->src_mac[0],eth->src_mac[1],eth->src_mac[2],eth->src_mac[3],eth->src_mac[4],eth->src_mac[5]);
    printf("    目标MAC地址 : %02x-%02x-%02x-%02x-%02x-%02x\n",eth->dst_mac[0],eth->dst_mac[1],eth->dst_mac[2],eth->dst_mac[3],eth->dst_mac[4],eth->dst_mac[5]);
    printf("    以太网类型: 0x%04x\n\n",ntohs(eth->eth_type));
}

//处理IP协议包
void handleIpPackage(ip_hdr *ip)
{
    printf("        IPv4:\n");
    printf("         版本:%u\n",ip->version);
    printf("         源IP地址:%d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
    printf("         目标IP地址:%d.%d.%d.%d\n\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
}
//处理TCP协议包
void handleTcpPackage(tcp_hdr *tcp)
{
    printf("            TCP协议信息:\n");
    printf("             本地端口号:%u\n",tcp->sport);
    printf("             目标端口号:%u\n",tcp->dport);
    printf("             序列号:%u ",tcp->seq);
    printf("             应答号:%u\n",tcp->ac);
    printf("             URG:%u ACK:%u PSH:%u RST:%u SYN:%u FIN:%u\n\n",tcp->URG,tcp->ACK,tcp->PSH,tcp->RST,tcp->SYN,tcp->FIN);
}

//处理UDP协议包
void handleUdpPackage(udp_hdr *udp)
{
    printf("            UDP协议信息:\n");
    printf("             本地端口号:%u\n",udp->sport);
    printf("             目标端口号:%u\n",udp->dport);
    printf("             总长度:%u\n\n",udp->tot_len);
}

//处理ARP协议包
void handleArpPackage(arp_hdr *arp)
{
    printf("    ARP协议信息:\n");
    printf("     硬件类型:1");//理论上是1，但是输出为256?
    //printf("     硬件类型:%u\n",arp->tohrd);
    printf("     协议类型:0x%04x\n",ntohs(arp->topro));
    printf("     硬件地址长度:%u\n",arp->hrd_addr_len);
    printf("     协议地址长度:%u\n",arp->pro_addr_len);
    printf("     源MAC地址:%02x-%02x-%02x-%02x-%02x-%02x\n",arp->sha[0],arp->sha[1],arp->sha[2],arp->sha[3],arp->sha[4],arp->sha[5]);
    printf("     源IP地址:%d.%d.%d.%d\n",arp->spa[0],arp->spa[1],arp->spa[2],arp->spa[3]);
    printf("     目标MAC地址:%02x-%02x-%02x-%02x-%02x-%02x\n",arp->tha[0],arp->tha[1],arp->tha[2],arp->tha[3],arp->tha[4],arp->tha[5]);
    printf("     目标IP地址:%d.%d.%d.%d\n\n",arp->tpa[0],arp->tpa[1],arp->tpa[2],arp->tpa[3]);
}
//handle IPv6 package
//TODO

#endif /* ProtocolHeadler_h */
