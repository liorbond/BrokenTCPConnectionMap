/*******************************************
**** Defines the callbacks for pcap_walk ***
*******************************************/

#ifndef __PACKET_UTILS__
#define __PACKET_UTILS__ // def guard

#include <pcap.h>

/* Simple callback prints the header
    for debug purposes
*/
void print_packet_header_handler(unsigned char*            args,
                                 const struct pcap_pkthdr* header,
                                 const unsigned char*      packet);


#endif // __PACKET_UTILS__