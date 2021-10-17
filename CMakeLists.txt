cmake_minimum_required(VERSION 3.16)
project(server LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_executable(${PROJECT_NAME} server.cpp util.hpp util.cpp)


# Boost

find_package(Boost 1.77 REQUIRED COMPONENTS chrono thread system coroutine)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC Boost::coroutine)
target_link_libraries(${PROJECT_NAME} PUBLIC Boost::headers)
target_link_libraries(${PROJECT_NAME} PRIVATE Boost::system)


# threads

set(THREADS_PREFER_PTHERAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)
