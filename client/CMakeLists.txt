project(http_tunnel_client)
cmake_minimum_required(VERSION 2.8)
set(OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/../bin)

#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_MULTITHREADED ON)
#set(CMAKE_BUILD_TYPE DEBUG)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../fiber_kit/include)


SET(EXECUTABLE_OUTPUT_PATH ${OUTDIR})

add_executable(http_tunnel_client main_http.cpp http_tunnel_client.cpp)

add_executable(https_tunnel_client main_https.cpp https_tunnel_client.cpp)

target_link_libraries(http_tunnel_client -Wl,--start-group pthread -Wl,--end-group)
target_link_libraries(https_tunnel_client -Wl,--start-group pthread ssl crypto -Wl,--end-group)

SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a")
MESSAGE(STATUS "cxx flags is ${CMAKE_CXX_FLAGS}")



