cmake_minimum_required(VERSION 3.10.2)
project(mtracecap)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -std=gnu++0x")

add_executable(mtracecap mtracecap.cc mtc_output.cc mtc_output.hh mtc_log.hh)
target_link_libraries(mtracecap trace pthread)