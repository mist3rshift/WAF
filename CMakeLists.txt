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
    lib/log.c
    lib/cJSON.c
)

add_executable(test_internal_log
    tests/test_internal_log.c
    src/internal_log.c
    lib/log.c
    lib/cJSON.c
)

target_compile_definitions(WAF PRIVATE LOG_USE_COLOR)