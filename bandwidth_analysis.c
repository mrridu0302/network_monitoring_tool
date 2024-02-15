#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <netinet/if_ether.h>
#include <time.h>

time_t prevTimestamp = 0;
unsigned long long totalBytes = 0;
void packetHandler(FILE * file, const struct pcap_pkthdr * pkthdr, const unsigned char * packet) {
  struct ethhdr * ethHeader = (struct ethhdr * ) packet;
  if (ntohs(ethHeader -> h_proto) == ETH_P_IP) {
    struct iphdr * ipHeader = (struct iphdr * )(packet + sizeof(struct ethhdr));
    if (ipHeader -> protocol == IPPROTO_TCP) {
      struct tcphdr * tcpHeader = (struct tcphdr * )(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      time_t currentTimestamp = pkthdr -> ts.tv_sec;
      unsigned long long bytes = pkthdr -> len;
      if (prevTimestamp != 0) {
        double bandwidth = (double)(bytes) / (currentTimestamp - prevTimestamp);
        printf("Bandwidth: %.2f bytes/s\n", bandwidth);
        fprintf(file, "Bandwidth: %.2f bytes/s\n", bandwidth);
        totalBytes += bytes;
      }
      prevTimestamp = currentTimestamp;
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
  FILE * file = fopen("bandwidth.txt", "wb");
  if (file == NULL) {
    perror("Error opening file");
    return 1;
  }
  pcap_loop(handle, 0, packetHandler, file);
  pcap_close(handle);
  fclose(file);
  printf("Total Bandwidth: %llu bytes\n", totalBytes);
  fprintf(file, "Total Bandwidth: %llu bytes\n", totalBytes);
  return 0;
}
