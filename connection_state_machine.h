#ifndef __CONECTION_STATE_MACHINE__
#define __CONECTION_STATE_MACHINE__

#include "application_connection_definitions.h"

INNER_STATUS advance_state(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state);

#endif // __CONECTION_STATE_MACHINE__