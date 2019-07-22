#include "my_pcap.h"

bool isHasIPHeader(const u_char* data){
    if(ntohs(getEthHeaderFromData(data)->ether_type) == 0x0800)
        return true;
    return false;
}

bool isHasTCPHeader(const u_char* data){
    if(isHasIPHeader(data) && getIPHeaderFromData(data)->protocol == 0x6)
        return true;
    return false;
}


struct ether_header* getEthHeaderFromData(const u_char* data){
    return (struct ether_header*)data;
}

struct iphdr* getIPHeaderFromData(const u_char* data){
    if(isHasIPHeader(data))
        return (struct iphdr*)(data + 14);
}

struct tcphdr* getTCPHeaderFromData(const u_char* data){
    if(isHasTCPHeader(data))
        return (struct tcphdr*)(data + 14 + getIPHeaderFromData(data)->ihl*4);
}


void printMAC(struct ether_header* data, bool isSRC){
    const u_char* addr = nullptr;
    if(isSRC){
        addr = data->ether_shost;
    }else{
        addr = data->ether_dhost;
    }
    for(int i = 0; i < 6; i++){
        printf("%02x:", *(addr+i));
    }
    printf("\b ");
}

void printIP(struct iphdr* data, bool isSRC){
    const u_char* addr = nullptr;
    if(isSRC){
        addr = (const u_char*)data + 12;
    }else{
        addr = (const u_char*)data + 16;
    }
    for (int i = 0; i < 4; i++){
        printf("%d.", *(addr+i));
    }
    printf("\b ");
}

void printPort(struct tcphdr* data, bool isSRC){
    if(isSRC){
        printf("%d", ntohs(data->th_sport));
    }else{
        printf("%d", ntohs(data->th_dport));
    }
}

void printTCPData(const u_char* data){
    const u_char* addr = getTCPData(data);
    for(int i = 0; i < 10; i++){
        if(getTCPDataLength(data) <= i)  break;
        printf("%02x ", *(addr + i));
    }
}

int getTCPDataLength(const u_char* data){
    return ntohs(getIPHeaderFromData(data)->tot_len) - getIPHeaderFromData(data)->ihl*4 - getTCPHeaderFromData(data)->th_off*4;
}

const u_char* getTCPData(const u_char* data){
    return data + 14 + getIPHeaderFromData(data)->ihl*4 + getTCPHeaderFromData(data)->th_off*4;
}
