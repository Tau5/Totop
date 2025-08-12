cmake_minimum_required(VERSION 3.31)
project(totop C)

set(CMAKE_C_STANDARD 11)

add_library(totop STATIC totop.c)
target_include_directories(totop
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(totop
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        m
)
add_executable(totop_example test.c)
target_link_libraries(totop_example PRIVATE totop)
add_compile_options(-Wall)
