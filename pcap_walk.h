/******************************************
**** Api for walking over existing pcap ***
******************************************/


#ifndef __PACKET_WALK__
#define __PACKET_WALK__ // def guard

#include "system_defenitions.h"
#include "packet_utils.h"

/**
 * Function responsible of parsing each packet in pcap 
 *  and running [handler] on it
 * Params:
 *  [pcap_path] - null terminted string contains the path of the pcap
 *  [handler]  - function pointer from utils pack that handles each packet
 * Return:
 *  INNER_STATUS::SUCCESS if succed
*/
INNER_STATUS pcap_walk(char*        pcap_path, 
                       pcap_handler handler);

#endif // __PACKET_WALK__