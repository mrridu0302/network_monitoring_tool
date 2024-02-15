#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <netinet/if_ether.h> 
#include <arpa/inet.h> 
#include <string.h>

#define MAX_UNIQUE_IPS 1000 
#define THRESHOLD 1000
struct SourceIP {
  char ip[INET_ADDRSTRLEN];
  int packetCount;
};
struct SourceIP sourceIPs[MAX_UNIQUE_IPS];
int uniqueIPCount = 0;
void updateSourceIPCount(const char * sourceIP) {
  int i;
  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "Error activating handle: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
    // Check if the source IP is already in the array for (i = 0; i < uniqueIPCount; ++i) {
    if (strcmp(sourceIPs[i].ip, sourceIP) == 0) {
      sourceIPs[i].packetCount++;
      return;
    }
  }
  // If not found, add the source IP to the array if (uniqueIPCount < MAX_UNIQUE_IPS) {
  strcpy(sourceIPs[uniqueIPCount].ip, sourceIP);
  sourceIPs[uniqueIPCount].packetCount = 1;
  uniqueIPCount++;
  FILE * file = fopen("output.txt", "a");
  if (file == NULL) {
    perror("Error opening file");
    return;
  }
  // Write the information to the file
  fprintf(file, "%s: %d packets\n", sourceIPs[uniqueIPCount - 1].ip, sourceIPs[uniqueIPCount - 1].packetCount);
  fclose(file);
}
}
void packetHandler(unsigned char * userData,
  const struct pcap_pkthdr * pkthdr,
    const unsigned char * packet) {
  struct ethhdr * ethHeader = (struct ethhdr * ) packet;
  if (ntohs(ethHeader -> h_proto) == ETHERTYPE_IP) {
    struct iphdr * ipHeader = (struct iphdr * )(packet + sizeof(struct ethhdr));
    if (ipHeader -> protocol == IPPROTO_TCP) {
      struct tcphdr * tcpHeader = (struct tcphdr * )(packet + sizeof(struct ethhdr) +
        sizeof(struct iphdr));
      // Extract source IP
      char sourceIP[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, & (ipHeader -> saddr), sourceIP, INET_ADDRSTRLEN);

      updateSourceIPCount(sourceIP);
    }
  }
}
int main() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * handle = pcap_create("enp0s3", errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Could not create handle: %s\n", errbuf);
    return 1;
  }
  if (pcap_set_snaplen(handle, BUFSIZ) != 0) {
    fprintf(stderr, "Error setting snapshot length\n");
    pcap_close(handle);
    return 1;
  }
  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "Error activating handle: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }
  pcap_loop(handle, 0, packetHandler, NULL);
  pcap_close(handle);
  return 0;
}
