#pragma once
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

bool isHasIPHeader(const u_char* data);
bool isHasTCPHeader(const u_char* data);

struct ether_header* getEthHeaderFromData(const u_char* data);
struct iphdr* getIPHeaderFromData(const u_char* data);
struct tcphdr* getTCPHeaderFromData(const u_char* data);

void printMAC(struct ether_header* data, bool isSRC);
void printIP(struct iphdr* data, bool isSRC);
void printPort(struct tcphdr* data, bool isSRC);
void printTCPData(const u_char* data);

int getTCPDataLength(const u_char* data);
const u_char* getTCPData(const u_char* data);
