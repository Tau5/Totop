cmake_minimum_required(VERSION 3.31)
project(totop C)

set(CMAKE_C_STANDARD 11)

add_library(totop STATIC library.c)
target_include_directories(totop
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(totop_example
        test.c
)
target_link_libraries(totop_example
        PRIVATE totop
        crypto
        ssl
        m
)
add_compile_options(-Wall)
