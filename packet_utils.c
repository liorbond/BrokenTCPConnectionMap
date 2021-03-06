#include <stdio.h>

#include "packet_utils.h"
#include "protocol_headers.h"
#include "application_connection_definitions.h"


#define OPTIONS_SIZE 20


void print_ip(u_int32_t ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

void print_packet_header_handler(unsigned char*            args,
                                 const struct pcap_pkthdr* header,
                                 const unsigned char*      packet) {
    // Unused
    (void)args;
    packet_info_t  packet_info;
    // Avoid constness of packet
    unsigned char* local_packet = (unsigned char*) packet;
    bpf_u_int32*   local_length = (bpf_u_int32*)   &header->len;
    static size_t  count        = 1;

    if(SUCCESS == get_tcpip_headers(&local_packet, local_length, &packet_info)) {
        printf("%d Source ip:", (int)count);
        print_ip(ntohl(packet_info.ip_header.saddr));
        printf(" Source port: %d", ntohs(packet_info.tcp_header.th_sport));
        printf(" Dest ip:");
        print_ip(ntohl(packet_info.ip_header.daddr));
        printf(" Dest port: %d\n", ntohs(packet_info.tcp_header.th_dport));
    } else {
        printf("Failed packet length is: %d\n", header->len);
    }

    count++;
    
}

void bad_connections_parser(applications_hash_table_t* application_table,
                            const struct pcap_pkthdr*  header,
                            const unsigned char*       packet) {

    packet_info_t              packet_info;

    // Avoid constness of packet
    unsigned char* local_packet = (unsigned char*) packet;
    bpf_u_int32*   local_length = (bpf_u_int32*)   &header->len;

    static size_t  count        = 0;

    count++;

    if(count == 96) {
        printf("hi");
    }

    if(SUCCESS == get_tcpip_headers(&local_packet, local_length, &packet_info)) {
        // Skip data packet
        if(OPTIONS_SIZE < *local_length) {
            return;
        }

        // Skip tcp push
        if(TH_PUSH == (TH_PUSH & packet_info.tcp_header.th_flags)) {
            return;
        }

        if(SUCCESS != insert(application_table, &packet_info, header)) {
            printf("%d ERROR: Failed inserting to the hash table\n", (int)count);
            return;
        }

    } else {
       // printf("ERROR: Failed packet length is: %d\n", header->len);
    }


}
