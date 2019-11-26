#include "tcp_connection_map.h"
#include <stdlib.h>

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
    return (s1->source_ip == s2->source_ip) &&
           (s1->dest_ip   == s2->dest_ip)   &&
           (s1->dest_port == s2->dest_port);
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

INNER_STATUS insert(applications_hash_table_t* const        table,
                    const application_stub_t* const         key,           
                    const specific_connection_info_t* const value) {
    application_hash_table_bucket_t* bucket = NULL;
    
    if(FAILURE == (_get_bucket(table, key, &bucket))) {
        // Logged @ function
        return FAILURE;
    } 

    // Stub wasn't in the table before
    if(NULL == bucket->bucket_data) {        
        bucket->bucket_size = 1;
        bucket->bucket_data = (application_hash_table_node_t*)malloc(sizeof(application_hash_table_node_t));

        // Deep copy key and value
        bucket->bucket_data[0].key                                   = *key;
        bucket->bucket_data[0].value.connections[value->source_port] = *value;
    } else {
        if(bucket->bucket_size >= HASH_TABLE_SIZE - 1)
        {
            printf("ERROR: bucket is too big");
            return FAILURE;
        }

        bucket->bucket_data[bucket->bucket_size].value.connections[value->source_port] = *value; 
        bucket->bucket_size++;
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


