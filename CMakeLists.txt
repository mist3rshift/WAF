cmake_minimum_required(VERSION 3.15)
project(WAF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(server
    src/server.c
    lib/log.c

)

target_compile_definitions(server PRIVATE LOG_USE_COLOR)