#include <net/ethernet.h>
#include <memory.h>
#include <stdio.h>

#include "protocol_headers.h"

// Analyzed from pcap
#define LINUX_COOCKED_LAYER_SIZE 16

/**
 * Local function skips ethernet header by changing the pointer and the size
 * Params:
 *  [io_packet]        - buffer holds the whole packet (from first byte of ethernet header)
 *  [io_packet_len]    - the length of the packet 
 * Return:
 *  INNER_STATUS::SUCCESS if done
*/
static INNER_STATUS _skip_linux_coocked_layer(unsigned char** io_packet,
                                              bpf_u_int32*    io_packet_len) {
    if(LINUX_COOCKED_LAYER_SIZE >= *io_packet_len) {
        printf("ERROR: Invalid packet\n");
        return FAILURE;
    }

    *io_packet     += LINUX_COOCKED_LAYER_SIZE;
    *io_packet_len -= LINUX_COOCKED_LAYER_SIZE;

    return SUCCESS;
}


INNER_STATUS get_tcpip_headers(unsigned char** io_packet,
                               bpf_u_int32*    io_packet_len,
                               packet_info_t*  o_packet_info) {
    if(SUCCESS != _skip_linux_coocked_layer(io_packet, io_packet_len)) {
        // Logged @ function
        return FAILURE;
    }

    if(SUCCESS != get_ip_header(io_packet, io_packet_len , &o_packet_info->ip_header)) {
        // Logged @ function
        return FAILURE;
    }

    if(IPVERSION != o_packet_info->ip_header.version) {
        //printf("NOTICE: Bad IP version (Probably ARP Packet)\n");
        return FAILURE;
    }

    if(TCP_PROTO_NUM != o_packet_info->ip_header.protocol) {
        //printf("NOTICE: Skipping non tcp protocol (Probably DNS Packet)\n");
        return FAILURE;
    }

    if(SUCCESS != get_tcp_header(io_packet, io_packet_len, &o_packet_info->tcp_header)) {
        // Logged @ function
        return FAILURE;
    }

    return SUCCESS;

}

INNER_STATUS get_ip_header    (unsigned char** io_packet, 
                               bpf_u_int32*    io_packet_len,
                               struct iphdr*   o_ip_header) {
    if(sizeof(struct iphdr) > *io_packet_len) {

        //printf("NOTICE: Skipping non ip packet\n");
        return FAILURE;
    }

    // No need to memcpy_s since it's already checked
    memcpy((void*)o_ip_header, (void*)*io_packet, sizeof(struct iphdr));

    *io_packet     += sizeof(struct iphdr);
    *io_packet_len -= sizeof(struct iphdr);

    return SUCCESS;
}

INNER_STATUS get_tcp_header   (unsigned char** io_packet, 
                               bpf_u_int32*    io_packet_len,
                               struct tcphdr*  o_tcp_header) {
    if(sizeof(struct tcphdr) > *io_packet_len) {

        //printf("NOTICE: Skipping non tcp packet\n");
        return FAILURE;
    }

    // No need to memcpy_s since it's already checked
    memcpy((void*)o_tcp_header, (void*)*io_packet, sizeof(struct tcphdr));

    *io_packet     += sizeof(struct tcphdr);
    *io_packet_len -= sizeof(struct tcphdr);

    return SUCCESS;
}
