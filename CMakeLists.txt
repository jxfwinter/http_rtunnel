cmake_minimum_required(VERSION 3.16)
project(http_rtunnel)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message("Setting build type to 'RelWithDebInfo' as none was specified.")
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
    #设置多种编译类型的选项
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

# http_tunnel_server
add_executable(http_tunnel_server
    ./server/main.cpp
    ./server/http_tunnel_server.h
    ./server/http_tunnel_server.cpp
    ./server/http_tunnel_session.h
    ./server/http_tunnel_session.cpp
    ./server/https_tunnel_session.h
    ./server/https_tunnel_session.cpp
    ./server/kconfig.cpp
    ./server/kconfig.h
    ./server/logger.cpp
    ./server/logger.h
    ./server/tunnel_session.cpp
    ./server/tunnel_session.h)
target_include_directories(http_tunnel_server PRIVATE include)
target_link_directories(http_tunnel_server PRIVATE lib)
target_link_libraries(http_tunnel_server PRIVATE
    -Wl,--start-group
    boost_log boost_log_setup boost_filesystem boost_thread boost_date_time boost_program_options boost_regex
    ssl pthread crypto
    -Wl,--end-group)
target_compile_features(http_tunnel_server PRIVATE cxx_std_20)
set_target_properties(http_tunnel_server PROPERTIES CXX_EXTENSIONS OFF)
set_target_properties(http_tunnel_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

# http_tunnel_client
add_executable(http_tunnel_client
    ./client/main_http.cpp
    ./client/http_tunnel_client.h
    ./client/http_tunnel_client.cpp
    ./client/pub.cpp)
target_include_directories(http_tunnel_client PRIVATE include)
# target_link_directories(http_tunnel_client PRIVATE lib)
target_link_libraries(http_tunnel_client PRIVATE pthread)
target_compile_features(http_tunnel_client PRIVATE cxx_std_11)
set_target_properties(http_tunnel_client PROPERTIES CXX_EXTENSIONS OFF)
set_target_properties(http_tunnel_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

# https_tunnel_client
add_executable(https_tunnel_client
    ./client/main_https.cpp
    ./client/https_tunnel_client.h
    ./client/https_tunnel_client.cpp
    ./client/pub.cpp)
target_include_directories(https_tunnel_client PRIVATE include)
# target_link_directories(https_tunnel_client PRIVATE lib)
target_link_libraries(https_tunnel_client PRIVATE pthread ssl crypto)
target_compile_features(https_tunnel_client PRIVATE cxx_std_11)
set_target_properties(https_tunnel_client PROPERTIES CXX_EXTENSIONS OFF)
set_target_properties(https_tunnel_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

# yield_http_server
add_executable(yield_http_server
    ./client/main_test_server.cpp
    ./client/http_api_server.h
    ./client/http_api_server.cpp
    ./client/pub.cpp)
target_include_directories(yield_http_server PRIVATE include)
# target_link_directories(yield_http_server PRIVATE lib)
target_link_libraries(yield_http_server PRIVATE pthread)
target_compile_features(yield_http_server PRIVATE cxx_std_11)
set_target_properties(yield_http_server PROPERTIES CXX_EXTENSIONS OFF)
set_target_properties(yield_http_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")



