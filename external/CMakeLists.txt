set(UPNPC_BUILD_STATIC ON CACHE BOOL "Build static library")
set(UPNPC_BUILD_SHARED OFF CACHE BOOL "Build shared library")
set(UPNPC_BUILD_TESTS OFF CACHE BOOL "Build test executables")

if (STATIC AND MSVC)
  foreach(VAR CMAKE_C_FLAGS_RELEASE)
    string(REPLACE "/MD" "" ${VAR} "${${VAR}}")
  endforeach()
endif()

add_subdirectory(miniupnpc)
add_subdirectory(gtest)

message(STATUS "Using ${ARCH_WIDTH}-bit LMDB from source tree")
add_subdirectory(liblmdb)
set(LMDB_INCLUDE "liblmdb" CACHE STRING "LMDB Include path")
set(LMDB_LIBRARY "lmdb" CACHE STRING "LMDB Library name")

include_directories(${LMDB_INCLUDE})
include_directories(boost/archive)

set_property(TARGET lmdb upnpc-static gtest gtest_main PROPERTY FOLDER "external")

if(MSVC)
  if (STATIC)
    set (UPNPC_FLAGS "/MT")
  endif()
  set_property(TARGET upnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267 -wd4996 ${UPNPC_FLAGS}")
elseif(FREEBSD)
  set_property(TARGET upnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -D_XOPEN_SOURCE=600 -Wno-undef -Wno-unused-result -Wno-unused-value")
else()
  set_property(TARGET upnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()


if(WIN32)
    set(SPARSEHASH_CONFIGURE_COMMAND
        COMMAND ${CMAKE_COMMAND} -E echo "Skipping CONFIGURE step... (not needed)")

    set(SPARSEHASH_BUILD_COMMAND
        COMMAND ${CMAKE_COMMAND} -E echo "Skipping BUILD step... (not needed)")

    set(SPARSEHASH_INSTALL_COMMAND
        COMMAND ${CMAKE_COMMAND} -E make_directory <INSTALL_DIR>/include
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/src/google <INSTALL_DIR>/include/google
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/src/sparsehash <INSTALL_DIR>/include/sparsehash
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/src/windows/google <INSTALL_DIR>/include/google
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/src/windows/sparsehash <INSTALL_DIR>/include/sparsehash)
else()
    set(SPARSEHASH_CONFIGURE_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy_directory "<SOURCE_DIR>" "<BINARY_DIR>"
        COMMAND cd "<BINARY_DIR>" && ./configure --prefix=<INSTALL_DIR> CXXFLAGS=-std=c++11)

    set(SPARSEHASH_BUILD_COMMAND
        cd "<BINARY_DIR>" && ${CMAKE_MAKE_PROGRAM})

    set(SPARSEHASH_INSTALL_COMMAND
        cd "<BINARY_DIR>" && ${CMAKE_MAKE_PROGRAM} install)
endif()

ExternalProject_Add(sparsehash
    GIT_REPOSITORY https://github.com/sparsehash/sparsehash.git
    GIT_TAG master
    GIT_SHALLOW ON
    GIT_PROGRESS OFF

    UPDATE_COMMAND ""
    PATCH_COMMAND ""

    CONFIGURE_COMMAND ${SPARSEHASH_CONFIGURE_COMMAND} LD_FLAGS=-lstdc++11
    BUILD_COMMAND ${SPARSEHASH_BUILD_COMMAND}
    BUILD_ALWAYS ON
    TEST_COMMAND ""
    INSTALL_COMMAND ${SPARSEHASH_INSTALL_COMMAND}
)

ExternalProject_Get_property(sparsehash INSTALL_DIR)
set(SPARSEHASH_ROOT "${INSTALL_DIR}")
set(SPARSEHASH_INCLUDE_DIRS "${SPARSEHASH_ROOT}/include")
mark_as_advanced(SPARSEHASH_ROOT SPARSEHASH_INCLUDE_DIRS)

add_library(sparsehash::sparsehash INTERFACE IMPORTED GLOBAL)
add_dependencies(sparsehash::sparsehash sparsehash)
