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
#include "ARPtools.h"

void init_pcd(pcap_t **pcd, char **dev);
void read_relayList(pcap_t *pcd); // TODO

int relayNum;
struct relaySession relayList[100];


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

    //TODO: read_relayList(pcd); 구현
    //TODO
    /*
    * 주기적으로 fake ARP packet을 보내는 sendFakeARP와
    * relayPackets를 각각 스레드로 나눠 동시에 진행
    */

    return 0;
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