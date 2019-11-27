#ifndef __TCP_CONNECTION_MAP__
#define __TCP_CONNECTION_MAP__

#include "application_connection_definitions.h"
#include "system_defenitions.h"

#define HASH_TABLE_SIZE 65535


/**
 * Implements each node of hash table
 * Params: 
 *  [key]   - The stub of the application connection
 *  [value] - Application information
*/
typedef struct application_hash_table_node {
    application_stub_t        key;
    application_information_t value;
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
 *  [table]       - The hash table to search in
 *  [key]         - The key we are searching for
 *  [o_value]     - OUT param pointer to the specific value
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS get_value(applications_hash_table_t* const        table,
                       const application_stub_t* const         key,
                       application_information_t**             o_value);

/**
 * Inserts the key and the value to the hash table
 * Paramas:
 *  [table] - The hash table to search in
 *  [key]   - The key we are inserting
 *  [value] - The value we are inserting
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS insert(applications_hash_table_t* const        table,
                    const application_stub_t* const         key,           
                    const specific_connection_info_t* const value);

/** 
 * Prints the data regarding the bad connections from the table
 * Params:
 * [table] - The hash table
 * Return:
 *  INNER_STATUS::SUCCESS if worked successfuly.
*/
INNER_STATUS print_table(applications_hash_table_t* const table);

/**
 * Free all table buckets
*/
void free_table_buckets(applications_hash_table_t* const table);  

#endif // __TCP_CONNECTION_MAP__