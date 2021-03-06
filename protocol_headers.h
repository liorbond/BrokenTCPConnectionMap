#ifndef __PROTOCOL_HEADERS_PARSER__
#define __PROTOCOL_HEADERS_PARSER__

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include "system_defenitions.h"

#define TCP_PROTO_NUM 6

typedef enum TCP_CONNECTION_STATE {
  STATE_TCP_ESTABLISHED = 1,
  STATE_FIRST_FIN_ACK,
  STATE_SECOND_FIN_ACK,
  STATE_TCP_CLOSE,
  PLACEHOLDER_STATE_NO_CONNECTION, // All the states after this state indicates the connection isn't created
  STATE_TCP_SYN,
  STATE_TCP_SYN_RE1,
  STATE_TCP_SYN_RE2,
  STATE_TCP_SYN_RE3,
  STATE_TCP_SYN_RE4,
  STATE_TCP_SYN_RE5,
  STATE_TCP_SYN_RE6,
  STATE_TCP_SYNACK,
  STATE_TCP_RESET,
  STATE_TCP_BAD_STATE
} TCP_CONNECTION_STATE;


typedef struct packet_info {
    struct iphdr  ip_header;
    struct tcphdr tcp_header;
} packet_info_t;

/**
 * Parse packet and return its ip and tcp header
 *  fails if protocol isn't tcp
 * Params:
 *  [io_packet]     - IN+OUT param buffer holds the whole packet (from first byte of ethernet header)
 *  [io_packet_len] - IN+OUT param the length of the packet
 *  [o_packet_info] - OUT param holds the headers
 * Return:
 *  INNER_STATUS::SUCCESS if succeeded
*/
INNER_STATUS get_tcpip_headers(unsigned char** io_packet,
                               bpf_u_int32*    io_packet_len,
                               packet_info_t*  o_packet_info);
/**
 * Parse packet and return its ip header
 * Params:
 *  [io_packet]     - IN+OUT param buffer holds the packet (from first byte of ip header)
 *  [io_packet_len] - IN+OUT param the length of the packet
 *  [o_ip_header]   - OUT param holds the header
 * Return:
 *  INNER_STATUS::SUCCESS if succeeded
*/
INNER_STATUS get_ip_header    (unsigned char** io_packet,
                               bpf_u_int32*    io_packet_len, 
                               struct iphdr*   o_ip_header);
/**
 * Parse packet and return its tcp header
 * Params:
 *  [io_packet]     - IN+OUT param buffer holds the packet (from first byte of ip header)
 *  [io_packet_len] - IN+OUT param the length of the packet
 *  [o_tcpp_header]   - OUT param holds the header
 * Return:
 *  INNER_STATUS::SUCCESS if succeeded
*/
INNER_STATUS get_tcp_header   (unsigned char** io_packet, 
                               bpf_u_int32*    io_packet_len,
                               struct tcphdr*  o_tcp_header);

INNER_STATUS reverse_tcpip_headers(const packet_info_t* const packet_info, packet_info_t* o_packet_info);

#endif // __PROTOCOL_HEADERS_PARSER__