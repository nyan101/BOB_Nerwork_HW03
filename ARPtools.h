//for packet capturing
#include <pcap.h>
//for structure
#include <netinet/ether.h>
#include <arpa/inet.h>

struct relaySession{
    struct in_addr    sendIP;

    struct in_addr    recvIP;
    struct ether_addr recvMAC; // real MAC address
};

int  convertIP2MAC(pcap_t *pcd, const struct in_addr IP, struct ether_addr *MAC);
void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC);
void makeARPpacket(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC,
                                   const struct in_addr recvIP, const struct ether_addr recvMAC, uint16_t ARPop);
void relayPackets(pcap_t *pcd, struct relaySession *relayList, int relayNum);