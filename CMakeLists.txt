cmake_minimum_required(VERSION 2.8.9)
project(msg_lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

set(LIB_SRCS src/msglib.c)

add_library(messaging SHARED ${LIB_SRCS})
include_directories(inc)
set_target_properties(messaging PROPERTIES PUBLIC_HEADER inc/msglib.h)
set_target_properties(messaging PROPERTIES SOVERSION "1")

install(TARGETS messaging DESTINATION lib PUBLIC_HEADER DESTINATION inc COMPONENT dev)

### Debian Package generation
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Franz Flasch") #required
include(CPack)
