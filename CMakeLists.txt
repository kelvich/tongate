cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

project(tongate)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -g -fno-omit-frame-pointer")

add_subdirectory(ton EXCLUDE_FROM_ALL)
add_subdirectory(src EXCLUDE_FROM_ALL)

add_executable(tongate src/tongate.cpp src/server.cpp)
target_include_directories(tongate PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ton/ $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/tongate/>)
target_link_libraries(tongate PUBLIC tdactor ton_crypto tl_api tdnet common tdfec overlay tl-utils adnl dht adnltest)

add_executable(client src/client.cpp)
target_include_directories(client PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ton/> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/tongate/)
target_link_libraries(client PUBLIC tdactor ton_crypto tl_api tdnet common tdfec overlay tl-utils adnl dht adnltest tl-lite-utils)
