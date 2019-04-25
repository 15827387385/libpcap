//
//  main.c
//  CsLab
//
//  Created by 张晓天 on 2019/4/25.
//  Copyright © 2019 张晓天. All rights reserved.
//


#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

//导入各协议处理函数的头文件
#include "ProtocolHeadler.h"

//数据结构声明


int main()
{
    //获得设备
    char *dev,errbuf[1024];
    dev=pcap_lookupdev(errbuf);
    //获得设备失败
    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        return 0;
    }
    printf("设备: %s\n", dev);
    
    //打开会话
    pcap_t *pcap_handle = pcap_open_live(dev,65535,1,0,errbuf);
    //打开会话失败
    if(pcap_handle==NULL){
        printf("%s\n",errbuf);
        return 0;
    }
    
    //获取网络号ip和掩码
    struct in_addr addr;
    bpf_u_int32 ipaddress, ipmask;
    char *dev_ip,*dev_mask;
    
    if(pcap_lookupnet(dev,&ipaddress,&ipmask,errbuf)==-1){
        printf("%s\n",errbuf);
        return 0;
    }
    //输出ip
    addr.s_addr=ipaddress;
    dev_ip=inet_ntoa(addr);
    printf("ip地址: %s\n",dev_ip);
    
    //输出掩码
    addr.s_addr=ipmask;
    dev_mask=inet_ntoa(addr);
    printf("子网掩码: %s\n",dev_mask);
    
    printf("----------------------分析-----------------------\n");
    int id=0;//传入回调函数记录ID
    //声明回调函数
    void pcap_callback(unsigned char * arg,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content);
    
    if(pcap_loop(pcap_handle,10,pcap_callback,(unsigned char *)&id)<0)
    {//接收数据包
        printf("错误\n");
        return 0;
    }
    
    pcap_close(pcap_handle);
    return(0);
}

void pcap_callback(unsigned char * arg,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content)
{
    static int id=1;
    printf("id=%d\n",id++);
    
    handlePackage(packet_header, packet_content);
    
    eth_hdr *eth;
    eth = (eth_hdr *)packet_content;
    handleEtherPackage(eth);
    
    //处理上层协议
    switch (ntohs(eth->eth_type))
    {
            //IPv4:0x0800
        case 0x0800:
        {
            ip_hdr *ip;
            ip = (ip_hdr*)(packet_content+sizeof(struct eth_hdr));
            handleIpPackage(ip);
            //处理上层协议
            switch (ip->protocol)
            {
                    //tcp
                case 6:
                {
                    tcp_hdr *tcp;
                    tcp = (tcp_hdr*)(packet_content+sizeof(struct eth_hdr)+sizeof(struct ip_hdr));
                    handleTcpPackage(tcp);
                    break;
                }
                    
                    //udp
                case 17:
                {
                    udp_hdr *udp;
                    udp = (udp_hdr*)(packet_content+sizeof(struct eth_hdr)+sizeof(struct ip_hdr));
                    handleUdpPackage(udp);
                }
                    
                    //其它协议
                default:
                {
                    printf("其它协议");
                    break;
                }
            }
            break;
        }
            
            //ARP:0x0806
        case 0x0806:
        {
            arp_hdr *arp;
            arp = (arp_hdr*)(packet_content+sizeof(struct eth_hdr));
            handleArpPackage(arp);
            break;
        }
            
            //RARP:0x8035
        case 0x8035:
        {
            printf("    RARP:0x8035");
            break;
        }
            
            
            //802.1Q tag: 0x8100
        case 0x8100:
        {
            printf("    0x8100");
            break;
        }
            
            //MPLS Label:0x8847
        case 0x8847:
        {
            printf("    0x8847");
            break;
        }
            
            //PPPoE:0x8864
        case 0x8864:
        {
            printf("    0x8864");
            break;
        }
            
            //IPV6: 0x86DD
        case 0x86DD:
        {
            printf("    0x86DD");
            break;
        }
            
            //其它类型
        default:
        {
            printf("    其它类型");
            break;
        }
    }
    printf("\n----------------------完成-----------------------\n");
    printf("\n\n");
}
