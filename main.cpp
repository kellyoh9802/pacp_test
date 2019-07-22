#include <my_pcap.h>
#include <stdio.h>
#include "my_pcap.h"

#define DEBUG

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
#ifndef DEBUG
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
#else
    char* dev = "ens33";
#endif
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("Ethernet\n");
    printf("=======================================\n");
    printf("Source MAC: ");
    printMAC(getEthHeaderFromData(packet), true);
    printf("\nDestination MAC: ");
    printMAC(getEthHeaderFromData(packet), false);
    printf("\n");
    printf("\n");
    if(isHasIPHeader(packet)){
        printf("IP\n");
        printf("=======================================\n");
        printf("Source IP: ");
        printIP(getIPHeaderFromData(packet), true);
        printf("\nDestination IP: ");
        printIP(getIPHeaderFromData(packet), false);
        printf("\n");
        printf("\n");
        if(isHasTCPHeader(packet)){
            printf("TCP\n");
            printf("=======================================\n");
            printf("Source port: ");
            printPort(getTCPHeaderFromData(packet), true);
            printf("\nDestiation port: ");
            printPort(getTCPHeaderFromData(packet), false);
            printf("\n");
            printTCPData(packet);
            printf("\n");
        }
    }
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
