cmake_minimum_required(VERSION 3.26)
project(encrypt_example)

set(CMAKE_CXX_STANDARD 17)

add_library(encrypt_example library.cpp)

find_package(OpenSSL)
