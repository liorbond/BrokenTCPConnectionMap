#ifndef __APPLICATION_CONNECTIONS_DEFINITIONS__
#define __APPLICATION_CONNECTIONS_DEFINITIONS__

#include "protocol_headers.h"
#include "system_defenitions.h"

#define TCP_PORT_MAX    65535

// Note: the word application used to describe each stub because it's common that every application differ in on of the params in the stub 

/**
 * Specifies the key of each application's connecion.
 * Note: Source port is usually OS defined and shouldn't be counted as part of the key
 *         Ofcourse its differ between each connection but this fact is counted in connection_node_t
 * Params:
 *  [source_ip] - Initiator ip (It's important to note that the direction should be considered)
 *  [dest_ip]   - Destination ip
 *  [dest_port] - Destination port
*/
typedef struct application_stub {
    u_int32_t source_ip;
    u_int32_t dest_ip;
    u_int16_t dest_port;
} application_stub_t;

/**
 * Indicates the state of the connection and the time its updated
 * Params:
 *  [timestamp]         - The timestamp when the state is updated  
 *  [connection_state]  - The state of the connection
*/
typedef struct connection_state {
    struct timeval       timestamp;
    TCP_CONNECTION_STATE connection_state;
} connection_state_t;

/**
 * Contains the data needed for each connection
 * Params:
 *  [source_port]             - Source port
 *  [timed_connection_state]  - The state of the connection
*/
typedef struct specific_connection_info {
    u_int16_t            source_port;
    connection_state_t   timed_connection_state;
} specific_connection_info_t;


/**
 * Implements each node of hash table
 * Params: 
 *  [connections] - The connections used by this application
 *  [value]       - Amount of bad_connections
*/
typedef struct application_information {
    specific_connection_info_t connections[TCP_PORT_MAX];
    size_t                     bad_connections;
} application_information_t;

/**
 * Finds the connection with the specified source_port from application_info
 * Params:
 *  [application_info] - application information contains all the connections
 *  [source_port]      - source port of the connection we are looking for
 *  [o_connection]     - OUT param will contain the connection
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS get_connection(application_information_t* const       application_info,
                            u_int16_t                              source_port,
                            specific_connection_info_t**           o_connection);
/**
 * Create application stub 
 * Params:
 *  [packet_info] - tcp/ip headersill contain the application stub
 *  [o_stub]      - OUT param will contain the application stub
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS create_application_stub(const packet_info_t* const      packet_info,
                                     application_stub_t*             o_stub);

/**
 * Create connection info from specified tcp packet
 * Params:
 *  [packet_info] - tcp/ip headersill contain the application stub
 *  [pcap_header] - Metadata of the connections
 *  [o_conn_info] - OUT param will contain the connection info
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS create_connection_info(const packet_info_t* const      packet_info,
                                    const struct pcap_pkthdr* const pcap_header,
                                    specific_connection_info_t*     o_conn_info);

/**
 * Create defualyt application info
 * Params:
 *  [o_application_info] - Out
 *  [o_stub]      - OUT param will contain the application_info
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS create_defualt_application_info(application_information_t* const o_application_info);


#endif // __APPLICATION_CONNECTIONS_DEFINITIONS__