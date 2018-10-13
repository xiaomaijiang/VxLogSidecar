cmake_minimum_required (VERSION 2.6)
project (CMake-Template)

aux_source_directory(. DIR_SRCS)

include(FindPkgConfig)
pkg_check_modules(PKGS REQUIRED apr-1)


include_directories(${PKGS_INCLUDE_DIRS})
link_directories(${PKGS_LIBRARY_DIRS})

set(CURL_LIBRARY "-lcurl") 
find_package(CURL REQUIRED) 
include_directories(${CURL_INCLUDE_DIR})

set(INC_DIR /usr/local/include) 
set(LINK_DIR /usr/local/lib)
include_directories(${INC_DIR})
link_directories(${LINK_DIR})

add_executable(VxLogSideCar ${DIR_SRCS})

target_link_libraries(VxLogSideCar ${CURL_LIBRARIES} zlog ${PKGS_LDFLAGS})