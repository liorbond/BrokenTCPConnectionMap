#include <stdio.h>
#include <stdlib.h>

#include "broken_tcp_connection_map.h"
#include "pcap_walk.h"

#define FILE_PATH_ARGUMENT_NUM 1
#define ARGUMENTS_ASKED        2

void map_broken_tcp_connections(char* pcap_path) {
    if(SUCCESS != pcap_walk(pcap_path, print_packet_header_handler)) {
        printf("ERROR: Failed to  map the pcap file %s\n", pcap_path);
        return;
    }
}

int main(int argc, char** argv) {
    if(ARGUMENTS_ASKED != argc) {
        printf("Usage: ./BrokenTCPConnectionMap [pcap_path]\n");
        return EXIT_FAILURE;
    }

    map_broken_tcp_connections(argv[FILE_PATH_ARGUMENT_NUM]);
    return EXIT_SUCCESS;
}