cmake_minimum_required(VERSION 3.0)
project(IronStack)

set(SRC src/main.cpp)
include_directories(include)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -Wall -Wextra -g -DPARANOIA_LEVEL=10")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -DPARANOIA_LEVEL=10")

add_executable(stack ${SRC})
