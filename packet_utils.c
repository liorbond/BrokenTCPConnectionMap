#include <stdio.h>
#include "packet_utils.h"

void print_packet_header_handler(unsigned char*            args,
                                 const struct pcap_pkthdr* header,
                                 const unsigned char*      packet) {
    // Unused
    (void)packet;
    (void)args;
    
    printf("Packet header length is %d\n", header->len);
    
}
