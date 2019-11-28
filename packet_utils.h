/*******************************************
**** Defines the callbacks for pcap_walk ***
*******************************************/

#ifndef __PACKET_UTILS__
#define __PACKET_UTILS__ // def guard

#include <pcap.h>

#include "tcp_connection_map.h"


/**
 * Prints ip formated as \d{0,3}.\d{0,3}.\d{0,3}.\d{0,3}
*/
void print_ip(u_int32_t ip);


/* Simple callback prints the header
    for debug purposes
*/
void print_packet_header_handler(u_char*                   args,
                                 const struct pcap_pkthdr* header,
                                 const unsigned char*      packet);

void bad_connections_parser(applications_hash_table_t* application_table,
                            const struct pcap_pkthdr*  header,
                            const unsigned char*       packet);
                


#endif // __PACKET_UTILS__