#include "connection_state_machine.h"

#define SYN1_DIFF 1
#define SYN2_DIFF 2 * SYN1_DIFF
#define SYN3_DIFF 2 * SYN2_DIFF
#define SYN4_DIFF 2 * SYN3_DIFF
#define SYN5_DIFF 2 * SYN4_DIFF
#define SYN6_DIFF 2 * SYN5_DIFF

void _handle_established(const packet_info_t* const packet_info,
                         application_information_t* o_application_information,
                         connection_state_t*        o_curr_state) {
    if(TH_ACK == packet_info->tcp_header.th_flags) {
        // Probably window ack, ignore
        return;
    }

    if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_CLOSE;
        return;
    }

    if(TH_FIN + TH_ACK != packet_info->tcp_header.th_flags) {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }

    o_curr_state->connection_state = STATE_FIRST_FIN_ACK;
}

void _handle_finack(const packet_info_t* const packet_info,
                    application_information_t* o_application_information,
                    connection_state_t*        o_curr_state) {
    if(TH_FIN + TH_ACK != packet_info->tcp_header.th_flags) {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }

    o_curr_state->connection_state = STATE_SECOND_FIN_ACK;
}

void _handle_finack1(const packet_info_t* const packet_info,
                    application_information_t* o_application_information,
                    connection_state_t*        o_curr_state) {
    if(TH_ACK != packet_info->tcp_header.th_flags) {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }

    o_curr_state->connection_state = STATE_TCP_CLOSE;
}

void _handle_closed(const packet_info_t* const packet_info,
                    application_information_t* o_application_information,
                    connection_state_t*        o_curr_state) {
    if(TH_SYN != packet_info->tcp_header.th_flags) {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }

    o_curr_state->connection_state = STATE_TCP_SYN;
}

void _handle_syn(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        if(SYN1_DIFF == header->ts.tv_sec - o_curr_state->timestamp.tv_sec) {
            o_curr_state->connection_state = STATE_TCP_SYN_RE1;
            o_curr_state->timestamp       = header->ts;
        } else {
            o_application_information->bad_connections++;
            // State is syn again
        }
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_syn1(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        if(SYN2_DIFF == header->ts.tv_sec - o_curr_state->timestamp.tv_sec) {
            o_curr_state->connection_state = STATE_TCP_SYN_RE2;
            o_curr_state->timestamp       = header->ts;
        } else {
            o_application_information->bad_connections++;
            o_curr_state->connection_state = STATE_TCP_SYN;
        }
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_syn2(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        if(SYN3_DIFF == header->ts.tv_sec - o_curr_state->timestamp.tv_sec) {
            o_curr_state->connection_state = STATE_TCP_SYN_RE3;
            o_curr_state->timestamp       = header->ts;
        } else {
            o_application_information->bad_connections++;
            o_curr_state->connection_state = STATE_TCP_SYN;
        }
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_syn3(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        if(SYN4_DIFF == header->ts.tv_sec - o_curr_state->timestamp.tv_sec) {
            o_curr_state->connection_state = STATE_TCP_SYN_RE4;
            o_curr_state->timestamp       = header->ts;
        } else {
            o_application_information->bad_connections++;
            o_curr_state->connection_state = STATE_TCP_SYN;
        }
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_syn4(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        if(SYN5_DIFF == header->ts.tv_sec - o_curr_state->timestamp.tv_sec) {
            o_curr_state->connection_state = STATE_TCP_SYN_RE5;
            o_curr_state->timestamp       = header->ts;
        } else {
            o_application_information->bad_connections++;
            o_curr_state->connection_state = STATE_TCP_SYN;
        }
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_syn5(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        if(SYN6_DIFF == header->ts.tv_sec - o_curr_state->timestamp.tv_sec) {
            o_curr_state->connection_state = STATE_TCP_SYN_RE6;
            o_curr_state->timestamp       = header->ts;
        } else {
            o_application_information->bad_connections++;
            o_curr_state->connection_state = STATE_TCP_SYN;
        }
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_syn6(const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_SYN == packet_info->tcp_header.th_flags) {
        o_application_information->bad_connections++;
        o_curr_state->connection_state = STATE_TCP_SYN;
    } else if(TH_RST + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_RESET;
    } else if(TH_SYN + TH_ACK == packet_info->tcp_header.th_flags) {
        o_curr_state->connection_state = STATE_TCP_SYNACK;   
    } else {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }
}

void _handle_synack(const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    if(TH_ACK != packet_info->tcp_header.th_flags) {
        printf("PCAP_ERROR: Bad state\n");
        o_application_information->bad_connections++;
    }

    o_curr_state->connection_state = STATE_TCP_ESTABLISHED;
}

INNER_STATUS advance_state(const struct pcap_pkthdr* const header,
                   const packet_info_t* const packet_info,
                   application_information_t* o_application_information,
                   connection_state_t*        o_curr_state) {
    switch(o_curr_state->connection_state) {
        case STATE_TCP_ESTABLISHED:
            _handle_established(packet_info, o_application_information, o_curr_state);
            break;
        case STATE_FIRST_FIN_ACK:
            _handle_finack(packet_info, o_application_information, o_curr_state);
            break;
        case STATE_SECOND_FIN_ACK:
            _handle_finack1(packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_CLOSE:
            _handle_closed(packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN:
            _handle_syn(header, packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN_RE1:
            _handle_syn1(header, packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN_RE2:
            _handle_syn2(header, packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN_RE3:
            _handle_syn3(header, packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN_RE4:
            _handle_syn4(header, packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN_RE5:
            _handle_syn5(header, packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYN_RE6:
            _handle_syn6(packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_SYNACK:
            _handle_synack(packet_info, o_application_information, o_curr_state);
            break;
        case STATE_TCP_RESET:
            _handle_closed(packet_info, o_application_information, o_curr_state);
            break;
        default:
            printf("ERROR: FSM inner logic error\n");
            return FAILURE;
    }

    return SUCCESS;

}