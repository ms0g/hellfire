cmake_minimum_required(VERSION 3.20)
project(hellfire)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a")
set(SCRIPTS_PATH "scripts/")

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/${SCRIPTS_PATH}
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/src/cli)

add_subdirectory(src)