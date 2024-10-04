cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project(demo)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if (NOT WIN32)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    endif()
endif()

add_compile_options(-std=c++11)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}, Platform: ${CMAKE_SYSTEM_NAME}, CXX_Flags: ${CMAKE_CXX_FLAGS}")

include_directories(${CMAKE_SOURCE_DIR}/third_party/)
include_directories(${CMAKE_SOURCE_DIR}/ftp/)

add_executable(${PROJECT_NAME} example/main.cpp)

if (NOT WIN32)
    target_link_libraries(${PROJECT_NAME} pthread)
endif()
