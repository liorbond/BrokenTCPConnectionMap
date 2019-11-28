#include <stdlib.h>

#include "tcp_connection_map.h"
#include "packet_utils.h"
#include "application_connection_definitions.h"

/**
 * Hash function
 * TODO: prpably should do something better then sum and %  
 * Paramas:
 *  [key]   - The key we are searching for
 * Return:
 *   bucket index
*/
static size_t _get_hash(const application_stub_t* const key) {
    if(NULL == key) {
        printf("ERROR: Bucket resolver received NULL key");
        return HASH_TABLE_SIZE;
    }
    __uint128_t sum = key->source_ip + 
                      key->dest_ip   +
                      key->dest_port;

    return sum % HASH_TABLE_SIZE;
}

/**
 * Returns the bucket of the key in the map
 * Paramas:
 *  [table] - The hash table to search in
 *  [key]   - The key we are searching for
 * Return:
 *  Pointer to bucket
*/
static INNER_STATUS _get_bucket(applications_hash_table_t* const table, 
                                const application_stub_t* const  key,
                                application_hash_table_bucket_t** o_bucket) {
    *o_bucket = NULL;

    if(NULL == key) {
        printf("ERROR: Bucket resolver received NULL key");
        return FAILURE;
    }
    
    size_t bucket_idx = _get_hash(key);

    if(HASH_TABLE_SIZE == bucket_idx) {
        // Logged @ function
        return FAILURE;
    }

    *o_bucket = &table->hash_table[bucket_idx];

    return SUCCESS;
}

/** 
 * Updates each application bad_connection counter
 * Params:
 * [table] - The hash table
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS update_bad_connections(applications_hash_table_t* const table) {
    size_t bucket_size = 0;
    for(size_t i = 0; i < HASH_TABLE_SIZE; ++i) {
        // Read the bucket size. Best leave it here instead in the for statement because performace issues
        bucket_size = table->hash_table[i].bucket_size;
        for(size_t j = 0; j < bucket_size; ++j) {
            for(size_t p = 0; p < TCP_PORT_MAX; ++p) {
                // The connection isn't established
                if(PLACEHOLDER_STATE_NO_CONNECTION < 
                   table->hash_table[i].bucket_data[j].value.connections[p].timed_connection_state.connectin_state) {
                       table->hash_table[i].bucket_data[j].value.bad_connections++;
                }
            }
        }
    }

    return SUCCESS;
}

/**
 * Compares between 2 keys  
 * Paramas:
 *  [s1] - Pointer to the first stub
 *  [s2] - Pointer to the second stub
 * Return:
 *  BOOLEAN::TRUE if equal BOOLEAN::FALSE else
 *
*/
static BOOLEAN _key_compare(const application_stub_t* const s1,
                            const application_stub_t* const s2) {
    if((s1->source_ip == s2->source_ip) &&
       (s1->dest_ip   == s2->dest_ip)   &&
       (s1->dest_port == s2->dest_port)) {
           return TRUE;
    }

    return FALSE;
}

INNER_STATUS get_value(applications_hash_table_t* const        table,
                       const application_stub_t* const         key,
                       application_information_t**             o_value) {
    if(NULL == o_value) {
        printf("ERROR: get_value() out param is NULL");
        return FAILURE;
    }
    
    *o_value                                = NULL;
    application_hash_table_bucket_t* bucket = NULL;
    
    if(FAILURE == (_get_bucket(table, key, &bucket))) {
        // Logged @ function
        return FAILURE;
    }  

    if(NULL == bucket) {
        // Logged @ function
        return FAILURE;
    }

    // Find the key in the bucket
    for(size_t i = 0; i < bucket->bucket_size; ++i) {
        if(TRUE == _key_compare(&bucket->bucket_data[i].key, key)) {
            *o_value = &bucket->bucket_data[i].value;
            return SUCCESS;
        }
    }

    return FAILURE;
}

INNER_STATUS insert(applications_hash_table_t* const table,
                    const packet_info_t* const       normal_packet_info,           
                    const struct pcap_pkthdr* const  header) {
    application_hash_table_bucket_t* normal_bucket  = NULL;
    application_hash_table_bucket_t* reverse_bucket = NULL;
    packet_info_t                    reverse_packet_info;
    application_stub_t               normal_key;
    application_stub_t               reverse_key;

    application_hash_table_bucket_t* bucket; 
    packet_info_t*                   packet_info;
    application_stub_t*              key;

    BOOLEAN                          reverse = FALSE;


    if(SUCCESS != reverse_tcpip_headers(normal_packet_info, &reverse_packet_info)) {
        // Logged @ function
        return FAILURE;
    }

    if(SUCCESS != create_application_stub(&reverse_packet_info, &reverse_key)) {
        // Logged @ function
        return FAILURE;
    }

    if(SUCCESS != (_get_bucket(table, &reverse_key, &reverse_bucket))) {
        // Logged @ function
        return FAILURE;
    } 

    if(SUCCESS != create_application_stub(normal_packet_info, &normal_key)) {
        // Logged @ function
        return FAILURE;
    }

    if(SUCCESS != (_get_bucket(table, &normal_key, &normal_bucket))) {
        // Logged @ function
        return FAILURE;
    }

    // Check if response
    for(size_t i = 0; i < reverse_bucket->bucket_size; ++i) {
        if(TRUE == _key_compare(&reverse_bucket->bucket_data[i].key, &reverse_key)) {
            bucket      = reverse_bucket;
            packet_info = &reverse_packet_info;
            key         = &reverse_key;

            reverse     = TRUE;
        }
    }

    if (FALSE == reverse) {
        bucket      = normal_bucket;
        packet_info = (packet_info_t*)normal_packet_info;
        key         = &normal_key;
    }

    // Stub wasn't in the table before
    if(NULL == bucket->bucket_data) {
        specific_connection_info_t value;

        if(SUCCESS != create_connection_info(packet_info, header, &value)) {
            // Logged @ function
            return FAILURE;
        }

        bucket->bucket_size = 1;
        bucket->bucket_data = (application_hash_table_node_t*)malloc(sizeof(application_hash_table_node_t));

        if(SUCCESS != create_defualt_application_info(&bucket->bucket_data[0].value)) {
            // Logged @ function
            return FAILURE;
        } 

        // Deep copy key and value
        bucket->bucket_data[0].key                                   = *key;
        bucket->bucket_data[0].value.connections[value.source_port]  = value;

    } else {
        // Check if the key in the map and insert the value
        for(size_t i = 0; i < bucket->bucket_size; ++i) {
            
            if(TRUE == _key_compare(&bucket->bucket_data[i].key, key)) {
                if(0 ==
                   bucket->bucket_data[bucket->bucket_size].value.connections[packet_info->tcp_header.th_sport].source_port) {
                    
                    specific_connection_info_t value;

                    if(SUCCESS != create_connection_info(packet_info, header, &value)) {
                        // Logged @ function
                        return FAILURE;
                    }

                    bucket->bucket_data[bucket->bucket_size].value.connections[value.source_port] = value;       
                } else {
                    // TODO: update status
                }
                
                return SUCCESS;
            }
        }

        if(bucket->bucket_size >= HASH_TABLE_SIZE - 1)
        {
            printf("ERROR: bucket is too big");
            return FAILURE;
        }

        bucket->bucket_data = (application_hash_table_node_t*)malloc((bucket->bucket_size + 1) *
                                                                      sizeof(application_hash_table_node_t));

        if(SUCCESS != create_defualt_application_info(&bucket->bucket_data[bucket->bucket_size].value)) {
            // Logged @ function
            return FAILURE;
        }

        specific_connection_info_t value;

        if(SUCCESS != create_connection_info(packet_info, header, &value)) {
            // Logged @ function
            return FAILURE;
        } 

        bucket->bucket_data[bucket->bucket_size].key                                   = *key;                                                              
        bucket->bucket_data[bucket->bucket_size].value.connections[value.source_port]  = value; 
        bucket->bucket_size++;
    }

    return SUCCESS;
}

INNER_STATUS print_table(applications_hash_table_t* const table) {
    if(SUCCESS != update_bad_connections(table)) {
        // Logged @ function
        return FAILURE;
    }

    size_t bucket_size = 0;
    size_t index       = 1;
    
    for(size_t i = 0; i < HASH_TABLE_SIZE; ++i) {
        // Read the bucket size. Best leave it here instead in the for statement because performace issues
        bucket_size = table->hash_table[i].bucket_size;
        for(size_t j = 0; j < bucket_size; ++j) {
            printf("%d. Application with source_ip: ", (int)index);
            print_ip(ntohl(table->hash_table[i].bucket_data[j].key.source_ip));
            printf(" dest_ip: ");
            print_ip(ntohl(table->hash_table[i].bucket_data[j].key.dest_ip));
            printf(" dest_port: %d\n", ntohs(table->hash_table[i].bucket_data[j].key.dest_port));
            printf("Amount of bad connections: %d \n", (int)table->hash_table[i].bucket_data[j].value.bad_connections);
            printf("List of source ports of connections:\n");
            
            for(size_t p = 0; p < TCP_PORT_MAX; ++p) {
                if(0 != table->hash_table[i].bucket_data[j].value.connections[p].source_port) {
                    printf("\t%d\n", ntohs(table->hash_table[i].bucket_data[j].value.connections[p].source_port));
                }
            }
            
            ++index;
        }
    }

    return SUCCESS;
}

INNER_STATUS print_table_summary(applications_hash_table_t* const table) {
    if(SUCCESS != update_bad_connections(table)) {
        // Logged @ function
        return FAILURE;
    }

    size_t bucket_size = 0;
    size_t index       = 1;
    
    for(size_t i = 0; i < HASH_TABLE_SIZE; ++i) {
        // Read the bucket size. Best leave it here instead in the for statement because performace issues
        bucket_size = table->hash_table[i].bucket_size;
        for(size_t j = 0; j < bucket_size; ++j) {
            if(0 == table->hash_table[i].bucket_data[j].value.bad_connections) {
                // No bad connection, continue
                continue;
            }

            printf("%d. Application with source_ip: ", (int)index);
            print_ip(ntohl(table->hash_table[i].bucket_data[j].key.source_ip));
            printf(" dest_ip: ");
            print_ip(ntohl(table->hash_table[i].bucket_data[j].key.dest_ip));
            printf(" dest_port: %d\n", ntohs(table->hash_table[i].bucket_data[j].key.dest_port));
            printf("Amount of bad connections: %d \n", (int)table->hash_table[i].bucket_data[j].value.bad_connections);
            printf("List of source ports of bad connections:\n");
            
            for(size_t p = 0; p < TCP_PORT_MAX; ++p) {
                // The connection isn't established
                if(PLACEHOLDER_STATE_NO_CONNECTION < 
                   table->hash_table[i].bucket_data[j].value.connections[p].timed_connection_state.connectin_state) {
                       printf("\t%d\n", ntohs(table->hash_table[i].bucket_data[j].value.connections[p].source_port));
                }
            }
            
            ++index;
        }
    }

    return SUCCESS;
}

void free_table_buckets(applications_hash_table_t* const table) {
    for(size_t i = 0; i < HASH_TABLE_SIZE; ++i) {
        if(NULL != table->hash_table[i].bucket_data && 
           0    != table->hash_table[i].bucket_size) {
               free(table->hash_table[i].bucket_data);
           }
    }
}


