#include <stdio.h>
#include <pcap.h>

#include "pcap_walk.h"

INNER_STATUS pcap_walk(char*        pcap_path,
                       pcap_handler handler) {
    pcap_t* pcap_handle;
    char    error_buff[PCAP_ERRBUF_SIZE];

    if (! (pcap_handle = pcap_open_offline(pcap_path, error_buff))) {
        fprintf(stderr,
                "ERROR: in opening pcap file, %s, for reading. %s\n",
                pcap_path, error_buff);

        return FAILURE;
    }

    // loop infinitly (cnt = 0) and no need to extra params to callback (user = NULL)
    pcap_loop(pcap_handle, 0, handler, NULL);

    return SUCCESS;    
}