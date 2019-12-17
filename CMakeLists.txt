cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

project(tongate)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -g -fno-omit-frame-pointer")

add_subdirectory(ton EXCLUDE_FROM_ALL)

add_executable(tongate tongate.cpp)
target_include_directories(tongate PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ton/>)
target_link_libraries(tongate PUBLIC tdactor ton_crypto tl_api tdnet common tdfec overlay tl-utils adnl dht adnltest)

add_executable(pong adnl-pong.cpp)
target_include_directories(pong PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ton/>)
target_link_libraries(pong PUBLIC tdactor ton_crypto tl_api tdnet common tl-utils adnl dht adnltest)
