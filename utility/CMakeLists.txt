PROJECT(utility)

FIND_PACKAGE(SQLite3 REQUIRED)
if (SQLite3_FOUND)
    include_directories(${SQLite3_INCLUDE_DIRS})
endif (SQLite3_FOUND)

file(GLOB SOURCES src/*)
file(GLOB HEADERS "include/*")

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} ${SQLite3_LIBRARIES})