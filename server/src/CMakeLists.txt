project(http_rproxy_server)
cmake_minimum_required(VERSION 2.8)
set(OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)

#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_MULTITHREADED ON)
#set(CMAKE_BUILD_TYPE DEBUG)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)

set(Boost_LIBRARIES boost_log boost_fiber boost_context boost_log_setup boost_thread boost_filesystem boost_program_options boost_regex boost_date_time)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../server_kit/include)

aux_source_directory(./ SRC_LIST)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../server_kit/lib)

SET(EXECUTABLE_OUTPUT_PATH ${OUTDIR})
add_executable(${PROJECT_NAME} ${SRC_LIST})

set(KLink_LIBRARIES klogger_sync request_api_server ws_call_server backtrace pthread dl crypto ssl)
target_link_libraries(${PROJECT_NAME} -Wl,--start-group ${Boost_LIBRARIES} ${KLink_LIBRARIES} -Wl,--end-group)
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
#   SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
MESSAGE(STATUS "cxx flags is ${CMAKE_CXX_FLAGS}")



