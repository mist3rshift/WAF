cmake_minimum_required(VERSION 3.15)
project(WAF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(WAF
    src/main.c
    src/proxy.c
    src/backend_connection.c
    src/client_handler.c
    src/request_parser.c
    src/firewall.c
    src/internal_log.c
    lib/log.c
    lib/cJSON.c
)

add_executable(test_internal_log
    tests/test_internal_log.c
    src/internal_log.c
    lib/log.c
    lib/cJSON.c
)

add_executable(test_parser
    tests/test_parser.c
    src/request_parser.c
    lib/log.c
    lib/cJSON.c
)

add_executable(test_firewall
    tests/test_firewall.c
    src/firewall.c
    lib/log.c
    lib/cJSON.c

)

target_compile_definitions(WAF PRIVATE LOG_USE_COLOR)