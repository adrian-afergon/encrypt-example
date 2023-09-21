cmake_minimum_required(VERSION 3.26)
project(encrypt_example)

set(CMAKE_CXX_STANDARD 17)

add_library(encrypt_example library.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(encrypt_example OpenSSL::Crypto)

add_executable(encrypt_example_test main.cpp)
target_link_libraries(encrypt_example_test encrypt_example)
