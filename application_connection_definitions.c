#include "application_connection_definitions.h"

INNER_STATUS get_connection(application_information_t* const application_info,
                            u_int16_t                        source_port,
                            specific_connection_info_t**     o_connection) {
    if(NULL == o_connection) {
        printf("ERROR: get_connection() out param is NULL");
        return FAILURE;
    }

    *o_connection = &application_info->connections[source_port];

    return SUCCESS;
}

INNER_STATUS create_connection_info(const packet_info_t* const      packet_info,
                                    const struct pcap_pkthdr* const pcap_header,
                                    application_stub_t*             o_stub,
                                    specific_connection_info_t*     o_conn_info) {
    o_stub->source_ip = packet_info->ip_header.saddr;
    o_stub->dest_ip   = packet_info->ip_header.daddr;
    o_stub->dest_port = packet_info->tcp_header.th_dport;

    o_conn_info->source_port                            = packet_info->tcp_header.th_sport;
    o_conn_info->timed_connection_state.timestamp       = pcap_header->ts;
    o_conn_info->timed_connection_state.connectin_state = STATE_TCP_ESTABLISHED; // Default state is ok (shouldn't be counted)

    return SUCCESS;
}

INNER_STATUS create_defualt_application_info(application_information_t* const application_info) {
    application_info->bad_connections                                            = 0;
    
    for(size_t i = 0; i < TCP_PORT_MAX; ++i) {
        // Dummy specific_connection_info_t
        application_info->connections[i].source_port                             = 0;
        application_info->connections[i].timed_connection_state.connectin_state  = STATE_TCP_ESTABLISHED;
        application_info->connections[i].timed_connection_state.timestamp.tv_sec = 0;
        application_info->connections[i].timed_connection_state.timestamp.tv_sec = 0;
    }

    return SUCCESS;
}