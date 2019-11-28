#include <stdio.h>
#include <pcap.h>

#include "pcap_walk.h"
#include "tcp_connection_map.h"

INNER_STATUS pcap_walk(const char* const pcap_path,
                       pcap_handler      handler) {
    pcap_t*                    pcap_handle;
    char                       error_buff[PCAP_ERRBUF_SIZE];
    applications_hash_table_t  applications_table;
    
    for(size_t i = 0; i < HASH_TABLE_SIZE; ++i) {
        applications_table.hash_table[i].bucket_data = NULL;
        applications_table.hash_table[i].bucket_size = 0;
    }

    if (! (pcap_handle = pcap_open_offline(pcap_path, error_buff))) {
        fprintf(stderr,
                "ERROR: in opening pcap file, %s, for reading. %s\n",
                pcap_path, error_buff);

        return FAILURE;
    }

    // loop infinitly (cnt = 0) and no need to extra params to callback (user = NULL)
    pcap_loop(pcap_handle, 0, handler, (u_char*)&applications_table);

    print_table(&applications_table);

    return SUCCESS;    
}