/********************************
*** Common system definitions ***
********************************/

#ifndef __SYSTEM_DEFINITIONS__
#define __SYSTEM_DEFINITIONS__ // def guard

/** Indicates function exit status
 *   choosen to implement as status and not as boolean for further use
*/
typedef enum INNER_STATUS {
    SUCCESS,
    SKIP,
    FAILURE
} INNER_STATUS;

typedef enum BOOLEAN {
    TRUE,
    FALSE
} BOOLEAN;


#endif // __SYSTEM_DEFINITIONS__