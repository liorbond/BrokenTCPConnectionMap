#ifndef __TCP_CONNECTION_MAP__
#define __TCP_CONNECTION_MAP__

#include "protocol_headers.h"
#include "system_defenitions.h"

#define TCP_PORT_MAX    65535
#define HASH_TABLE_SIZE 65535

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
    TCP_CONNECTION_STATE connectin_state;
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
 *  [key]   - The stub of the application connection
 *  [value] - Array of connections used by this application
*/
typedef struct application_hash_table_node {
    application_stub_t         key;
    specific_connection_info_t value[TCP_PORT_MAX];
} application_hash_table_node_t;

/**
 * Implemets applications hash table bucket
 * Params:
 *  [bucket_data] - The bucket
 *  [bucket_size] - Bucket size
*/
typedef struct application_hash_table_bucket {
    application_hash_table_node_t* bucket_data;
    size_t                         bucket_size;
} application_hash_table_bucket_t;

/**
 * Implemets applications hash table
 *  Maximum size of bucket is: [max_uint64_t + max_uint16_t] % HASH_TABLE_SIZE
 *  Remove unsupported
 * Params:
 *  [hash_table] - Array of HASH_TABLE_SIZE buckets
*/
typedef struct applications_hash_table {
    application_hash_table_bucket_t hash_table[HASH_TABLE_SIZE];
} applications_hash_table_t;

/**
 * Returns the value of the key in the map  
 * Paramas:
 *  [table] - The hash table to search in
 *  [key] - The key we are searching for
 * Return:
 *  Pointer to the specific value (NULL if the isn't in the map)
*/
specific_connection_info_t* get_value(applications_hash_table_t*  table,
                                      application_stub_t*         key);

/**
 * Inserts the key and the value to the hash table
 * Paramas:
 *  [table] - The hash table to search in
 *  [key]   - The key we are inserting
 *  [value] - The value we are inserting
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS                insert   (applications_hash_table_t*  table,
                                      application_stub_t*         key,
                                      specific_connection_info_t* value);

/**
 * Free all table buckets
*/
void                        free_table_buckets(applications_hash_table_t*  table);  

#endif // __TCP_CONNECTION_MAP__