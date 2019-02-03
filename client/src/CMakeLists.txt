project(http_rproxy_client)
cmake_minimum_required(VERSION 2.8)
set(OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)

#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_MULTITHREADED ON)
#set(CMAKE_BUILD_TYPE DEBUG)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../server/fiber_kit/include)

aux_source_directory(./ SRC_LIST)

link_directories()

SET(EXECUTABLE_OUTPUT_PATH ${OUTDIR})
add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} -Wl,--start-group pthread -Wl,--end-group)
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
MESSAGE(STATUS "cxx flags is ${CMAKE_CXX_FLAGS}")



