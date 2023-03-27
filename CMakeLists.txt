cmake_minimum_required(VERSION 3.20)
project(hellfire)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a")

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/scripts/
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/cli)

add_subdirectory(cli)
add_subdirectory(core)
add_subdirectory(utility)