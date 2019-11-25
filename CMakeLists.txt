cmake_minimum_required(VERSION 2.8)

project(BrokenTCPConnectionMap)

include(FindPCAP.cmake)

file(GLOB SOURCE_FILES
    "*.c"
)

SET(GCC_COVERAGE_COMPILE_FLAGS "-Werror -Wall -Wextra -g")
add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})

add_executable(BrokenTCPConnectionMap ${SOURCE_FILES})
target_link_libraries(BrokenTCPConnectionMap ${PCAP_LIBRARY})
