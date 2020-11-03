cmake_minimum_required(VERSION 2.8.6)

set(VERSION "0.2")

enable_language(C)
enable_language(CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_CONFIGURATION_TYPES Debug RelWithDebInfo Release CACHE TYPE INTERNAL)
set(CMAKE_SKIP_INSTALL_RULES ON)
set(CMAKE_SKIP_PACKAGE_ALL_DEPENDENCY ON)
set(CMAKE_SUPPRESS_REGENERATION ON)
if (WIN32)
 option(CMAKE_USE_WIN32_THREADS_INIT "using WIN32 threads" ON)
endif()

project(Karbowanec)

option(WITH_LITE_WALLET "Lite wallet specific" OFF)

if(WITH_LITE_WALLET)
  add_definitions("-DUSE_LITE_WALLET")
endif()

include_directories(include src external "${CMAKE_BINARY_DIR}/version")

# Check whether we're on a 32-bit or 64-bit system
if(CMAKE_SIZEOF_VOID_P EQUAL "8")
  set(DEFAULT_BUILD_64 ON)
else()
  set(DEFAULT_BUILD_64 OFF)
endif()
option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

if(BUILD_64)
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()
message(STATUS "Building for a ${ARCH_WIDTH}-bit system")

if(APPLE OR FREEBSD)
	include_directories(SYSTEM /usr/include/malloc)
	if(POLICY CMP0042)
		cmake_policy(SET CMP0042 NEW)
	endif()
	enable_language(ASM)
endif()

if(MSVC)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Windows)
elseif(APPLE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/OSX)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Posix)
elseif(FREEBSD)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/FreeBSD)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Posix)
elseif(ANDROID)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Android)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Posix)
else()
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Linux)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Platform/Posix)
endif()

if(NOT MSVC AND NOT APPLE)
	include_directories(src/Platform/Windows)
	include(TestCXXAcceptsFlag)
	include(CheckCCompilerFlag)
	if (NOT ARCH)
		set(ARCH default CACHE STRING "CPU to build for: -march value or default to not pass -march at all")
	endif()
	message(STATUS "Building on ${CMAKE_SYSTEM_PROCESSOR}")
	if(ARCH STREQUAL "default")
		set(ARCH_FLAG "")
	else()
		set(ARCH_FLAG "-march=${ARCH}")
		if(ARCH STREQUAL "native")
			check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
			if (NOT CC_SUPPORTS_MARCH_NATIVE)
				check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
				if (CC_SUPPORTS_MTUNE_NATIVE)
					set(ARCH_FLAG "-mtune=${ARCH}")
				else()
					set(ARCH_FLAG "")
				endif()
			endif()
		endif()
	endif()
endif()

# ARCH defines the target architecture, either by an explicit identifier or
# one of the following two keywords. By default, ARCH a value of 'native':
# target arch = host arch, binary is not portable. When ARCH is set to the
# string 'default', no -march arg is passed, which creates a binary that is
# portable across processors in the same family as host processor.	In cases
# when ARCH is not set to an explicit identifier, cmake's builtin is used
# to identify the target architecture, to direct logic in this cmake script.
# Since ARCH is a cached variable, it will not be set on first cmake invocation.
if (NOT ARCH_ID)
	if (NOT ARCH OR ARCH STREQUAL "" OR ARCH STREQUAL "native" OR ARCH STREQUAL "default")
		if(CMAKE_SYSTEM_PROCESSOR STREQUAL "")
			set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
		endif()
		set(ARCH_ID "${CMAKE_SYSTEM_PROCESSOR}")
	else()
		set(ARCH_ID "${ARCH}")
	endif()
endif()

string(TOLOWER "${ARCH_ID}" ARM_ID)
string(SUBSTRING "${ARM_ID}" 0 3 ARM_TEST)

if (ARM_TEST STREQUAL "arm")
	set(ARM 1)
	string(SUBSTRING "${ARM_ID}" 0 5 ARM_TEST)
	if (ARM_TEST STREQUAL "armv7")
		set(ARM7 1)
		message(STATUS "Setting -march=armv8-a+fp+simd for ARMv8")
		set(ARCH_FLAG "-march=armv8-a+fp+simd")
	endif()
endif()

if (ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
	set(ARM 1)
	set(ARM8 1)
endif()

# Manual ARCH options for ARM
if(ARM7) # ARMv7 Pi 3/4 32Bit
	CHECK_CXX_ACCEPTS_FLAG("-march=armv8-a" TRY_ARCH)
	if(TRY_ARCH)
		message(STATUS "Setting march=armv8-a for ARMv7")
		set(ARCH_FLAG "-march=armv8-a")
	endif()
elseif(ARM8) # ARMv8 Pi 3/4 64Bit
	CHECK_CXX_ACCEPTS_FLAG("-march=armv8-a+fp+simd" TRY_ARCH)
	if(TRY_ARCH)
		message(STATUS "Setting -march=armv8-a+fp+simd for ARMv8")
		set(ARCH_FLAG "-march=armv8-a+fp+simd")
	endif()
endif()

# Check support for AES
option(NO_AES "Explicitly disable AES support" ${NO_AES})

if(NO_AES) # No AES
	message(STATUS "AES support explicitly disabled")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_AES")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNO_AES")
elseif(NOT ARM AND NOT MSVC AND NOT PPC64LE) # x86/64
	message(STATUS "AES support enabled")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARCH_FLAG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ARCH_FLAG}")

# Check and set fpu and float settings
if(ARM)
message(STATUS "Setting FPU Flags for ARM Processors")

	if(NOT ARM8)
		# FPU
		CHECK_CXX_ACCEPTS_FLAG(-mfpu=neon-vfpv4 CXX_ACCEPTS_NEON_1)
		CHECK_CXX_ACCEPTS_FLAG(-mfpu=neon-fp-armv8 CXX_ACCEPTS_NEON_2)
		# FLOAT
		CHECK_CXX_ACCEPTS_FLAG(-mfloat-abi=hard CXX_ACCEPTS_MFLOAT_HARD)
	endif()

	if(ARM8)
		CHECK_CXX_ACCEPTS_FLAG(-mfix-cortex-a53-835769 CXX_ACCEPTS_MFIX_CORTEX_A53_835769)
		CHECK_CXX_ACCEPTS_FLAG(-mfix-cortex-a53-843419 CXX_ACCEPTS_MFIX_CORTEX_A53_843419)
	endif()

	if(ARM7)

		if(CXX_ACCEPTS_NEON_2)
			message(STATUS "Setting mfpu=neon-fp-armv8 for ARMv7")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=neon-fp-armv8")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=neon-fp-armv8")
		endif()

		if(CXX_ACCEPTS_NEON_1 AND NOT CXX_ACCEPTS_NEON_2)
			message(STATUS "Setting mfpu=neon-vfpv for ARMv7")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=neon-vfpv")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=neon-vfpv")
		endif()

		if(CXX_ACCEPTS_MFLOAT_HARD)
			message(STATUS "Setting Hardware ABI for Floating Point")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=hard")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=hard")
		endif()

	endif(ARM7)

	if(ARM8)

		if(CXX_ACCEPTS_MFIX_CORTEX_A53_835769)
			message(STATUS "Enabling Cortex-A53 workaround 835769")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-835769")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfix-cortex-a53-835769")
		endif()

		if(CXX_ACCEPTS_MFIX_CORTEX_A53_843419)
			message(STATUS "Enabling Cortex-A53 workaround 843419")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-843419")
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfix-cortex-a53-843419")
		endif()

	endif(ARM8)

endif(ARM)

set(STATIC ${MSVC} CACHE BOOL "Link libraries statically")

if(MSVC)
	add_definitions("/bigobj /MP /W3 /GS- /D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /D_VARIADIC_MAX=8 /D__SSE4_1__")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10485760")
	if(STATIC)
		foreach(VAR CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE)
			string(REPLACE "/MD" "/MT" ${VAR} "${${VAR}}")
		endforeach()
	endif()
	include_directories(SYSTEM src/platform/msc)
	add_definitions(/DHAVE_ROTR)
else()
	if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
		# This option has no effect in glibc version less than 2.20.
		# Since glibc 2.20 _BSD_SOURCE is deprecated, this macro is recomended instead
		add_definitions("-D_DEFAULT_SOURCE -D_GNU_SOURCE")
	endif()
	if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
		set(WARNINGS "${WARNINGS} -Wno-error=mismatched-tags -Wno-error=null-conversion -Wno-overloaded-shift-op-parentheses -Wno-error=shift-count-overflow -Wno-error=tautological-constant-out-of-range-compare -Wno-error=unused-private-field -Wno-error=unneeded-internal-declaration -Wno-error=unused-function")
		if(ANDROID)
			set(WARNINGS "${WARNINGS} -Wno-unused-lambda-capture")
		endif()
		if(ARM)
			set(WARNINGS "${WARNINGS} -Wno-error=inline-asm")
		endif()
	else()
		set(WARNINGS "${WARNINGS} -Wlogical-op -Wno-error=maybe-uninitialized -Wno-error=clobbered -Wno-error=unused-but-set-variable")
	endif()
  
	if(MINGW)
		set(WARNINGS "${WARNINGS} -Wno-error=unused-value")
		set(MINGW_FLAG "-DWIN32_LEAN_AND_MEAN")
		include_directories(SYSTEM src/platform/mingw)
	else()
		set(MINGW_FLAG "")
	endif()
	if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_C_COMPILER_VERSION VERSION_LESS 5.1))
		set(WARNINGS "${WARNINGS} -Wno-error=odr")
		add_definitions(/DHAVE_ROTR)
	endif()
	set(C_WARNINGS "-Waggregate-return -Wnested-externs -Wold-style-definition -Wstrict-prototypes")
	set(CXX_WARNINGS "-Wno-reorder -Wno-missing-field-initializers")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 ${MINGW_FLAG} ${WARNINGS} ${C_WARNINGS}")
	if(NOT APPLE)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
	endif()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${MINGW_FLAG} ${WARNINGS} ${CXX_WARNINGS}")
	if(APPLE)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DGTEST_HAS_TR1_TUPLE=0")
	endif()
	if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8))
		set(DEBUG_FLAGS "-g3 -Og")
	else()
		set(DEBUG_FLAGS "-g3 -O0")
	endif()
	set(RELEASE_FLAGS "-g3 -O0")
	
	# With GCC 6.1.1 the compiled binary malfunctions due to aliasing. Until that
	# is fixed in the code (Issue #847), force compiler to be conservative.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing")
	# Disable aggressive floating-point optimizations to make CN-GPU work correctly.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing -fno-fast-math")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing -fno-fast-math")
	
	if(NOT DEFINED USE_LTO_DEFAULT)
		set(USE_LTO_DEFAULT false)
	endif()
	set(USE_LTO ${USE_LTO_DEFAULT} CACHE BOOL "Use Link-Time Optimization (Release mode only)")

	if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
		# There is a clang bug that does not allow to compile code that uses AES-NI intrinsics if -flto is enabled, so explicitly disable
		set(USE_LTO false)
	endif()

	if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND NOT ANDROID)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes -msse4.1 -mavx -mavx2")
	endif()
	
	if(USE_LTO)
		set(RELEASE_FLAGS "${RELEASE_FLAGS} -flto")
		if(STATIC)
			set(RELEASE_FLAGS "${RELEASE_FLAGS} -ffat-lto-objects")
		endif()
		# Since gcc 4.9 the LTO format is non-standard (slim), so we need the gcc-specific ar and ranlib binaries
		if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.0) AND NOT OPENBSD AND NOT DRAGONFLY)
			# When invoking cmake on distributions on which gcc's binaries are prefixed
			# with an arch-specific triplet, the user must specify -DCHOST=<prefix>
			if (DEFINED CHOST)
				set(CMAKE_AR "${CHOST}-gcc-ar")
				set(CMAKE_RANLIB "${CHOST}-gcc-ranlib")
			else()
				set(CMAKE_AR "gcc-ar")
				set(CMAKE_RANLIB "gcc-ranlib")
			endif()
		endif()
	endif()

endif()

if(APPLE)
	add_definitions(/DHAVE_ROTR)
endif()

if(ARM)
	add_definitions(/DARM)
endif()

if(ANDROID AND NOT BUILD_GUI_DEPS STREQUAL "ON" OR IOS)
	#From Android 5: "only position independent executables (PIE) are supported" 
	message(STATUS "Enabling PIE executable")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -DANDROID -DBOOST_COROUTINES_NO_DEPRECATION_WARNING")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -pie -ldl -pthread")
endif()

if(ANDROID AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND ARCH STREQUAL "i686")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mstackrealign")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mstackrealign")
endif()

if(STATIC)
	if(MINGW)
		set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
	endif()
	set(Boost_NO_BOOST_CMAKE ON)
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_USE_STATIC_RUNTIME ON)
endif()

find_package(Boost REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options coroutine context atomic)
message(STATUS "Boost Found: ${Boost_INCLUDE_DIRS}")
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

set(CMAKE_FIND_LIBRARY_SUFFIXES ${OLD_LIB_SUFFIXES})
if(NOT Boost_FOUND)
	die("Could not find Boost libraries, please make sure you have installed Boost or libboost-all-dev (1.58) or the equivalent")
elseif(Boost_FOUND)
	message(STATUS "Found Boost Version: ${Boost_VERSION}")
endif()

# We have to look for Homebrew OpenSSL a bit differently
# Borrowed from https://github.com/tarantool/tarantool/commit/6eab201af1843f53a833c8928dc58fceffa08147
if (APPLE)
		find_program(HOMEBREW_EXECUTABLE brew)
		execute_process(COMMAND ${HOMEBREW_EXECUTABLE} --prefix openssl
						OUTPUT_VARIABLE HOMEBREW_OPENSSL
						OUTPUT_STRIP_TRAILING_WHITESPACE)
		if (DEFINED HOMEBREW_OPENSSL)
				if (NOT DEFINED OPENSSL_ROOT_DIR)
						message(STATUS "Setting OpenSSL root to ${HOMEBREW_OPENSSL}")
						set(OPENSSL_ROOT_DIR "${HOMEBREW_OPENSSL}")
				endif ()
		endif ()
endif ()

find_package(OpenSSL)

if (NOT OPENSSL_FOUND)
		find_package(PkgConfig)

		if (PKG_CONFIG_FOUND)
				pkg_search_module(OPENSSL openssl)
		endif()
endif()

if (OPENSSL_FOUND)
		## On non MSVC build systems, we need to link ldl with the static OpenSSL library
		if (NOT MSVC)
				set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};dl")
		endif ()

		include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
		message(STATUS "OpenSSL Found: ${OPENSSL_INCLUDE_DIR}")
		message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
	
	if (STATIC)
		set (OPENSSL_USE_STATIC_LIBS ON)
	endif ()
	if (MSVC)
		set(OPENSSL_MSVC_STATIC_RT ON)
	endif ()
else ()
		message(STATUS "OpenSSL Found: No... Skipping...")
endif ()

if(MINGW)
	string(REGEX MATCH "^[^/]:/[^/]*" msys2_install_path "${CMAKE_C_COMPILER}")
	message(STATUS "MSYS location: ${msys2_install_path}")
	set(CMAKE_INCLUDE_PATH "${msys2_install_path}/mingw${ARCH_WIDTH}/include")
	# This is necessary because otherwise CMake will make Boost libraries -lfoo
	# rather than a full path. Unfortunately, this makes the shared libraries get
	# linked due to a bug in CMake which misses putting -static flags around the
	# -lfoo arguments.
	set(DEFLIB ${msys2_install_path}/mingw${ARCH_WIDTH}/lib)
	list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
	list(REMOVE_ITEM CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
endif()

if(STATIC)
	if(MSVC)
		set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .dll.a .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
	else()
		set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
	endif()
endif()

if(MINGW)
	set(Boost_LIBRARIES "${Boost_LIBRARIES};ws2_32;mswsock;iphlpapi")
elseif(APPLE OR OPENBSD OR ANDROID)
	set(Boost_LIBRARIES "${Boost_LIBRARIES}")
elseif(NOT MSVC)
	set(Boost_LIBRARIES "${Boost_LIBRARIES};rt")
endif()

if(MINGW)
	set(EXTRA_LIBRARIES mswsock;ws2_32;iphlpapi)
elseif(APPLE OR OPENBSD OR ANDROID)
	set(EXTRA_LIBRARIES "")
elseif(FREEBSD)
	set(EXTRA_LIBRARIES execinfo)
elseif(DRAGONFLY)
	find_library(COMPAT compat)
	set(EXTRA_LIBRARIES execinfo ${COMPAT})
elseif(NOT MSVC)
	find_library(RT rt)
	set(EXTRA_LIBRARIES ${RT})
endif()

list(APPEND EXTRA_LIBRARIES ${CMAKE_DL_LIBS})

if(ANDROID AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
	set(ATOMIC ${BOOST_LIBRARYDIR}/libboost_atomic.a)
	set(THREAD ${BOOST_LIBRARYDIR}/libboost_thread.a)
	find_library(THREAD thread)
	list(APPEND EXTRA_LIBRARIES ${THREAD})
	if(ARCH_WIDTH EQUAL "32")
		find_library(ATOMIC atomic)
		list(APPEND EXTRA_LIBRARIES ${ATOMIC})
	endif()
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/src/version.cmake")

# option(BUILD_TESTS "Build tests." ON)

if(BUILD_TESTS)
	add_subdirectory(tests)
	enable_testing()
endif()

if (UNIX AND NOT APPLE)
	# Note that at the time of this writing the -Wstrict-prototypes flag added below will make this fail
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads)
endif()

add_subdirectory(external)

# Final setup for miniupnpc
if(STATIC OR IOS)
 #if(UPNP_STATIC OR IOS)
	add_definitions("-DUPNP_STATIC -DMINIUPNP_STATICLIB -DUPNPC_BUILD_STATIC")
 else()
	add_definitions("-DUPNP_DYNAMIC")
	include_directories(${UPNP_INCLUDE})
 endif()

add_subdirectory(src)

set(COMMIT_ID_IN_VERSION ON CACHE BOOL "Include commit ID in version")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/version")
if (NOT COMMIT_ID_IN_VERSION)
	set(VERSION "${VERSION}-unknown")
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version/version.h")
	add_custom_target(version ALL)
elseif(DEFINED COMMIT)
	string(REPLACE "." "\\." VERSION_RE "${VERSION}")
	if(NOT REFS MATCHES "(\\(|, )tag: v${VERSION_RE}(\\)|, )")
		set(VERSION "${VERSION}-g${COMMIT}")
	endif()
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version/version.h")
	add_custom_target(version ALL)
else()
	find_package(Git QUIET)
	if(Git_FOUND OR GIT_FOUND)
		message(STATUS "Found Git: ${GIT_EXECUTABLE}")
		add_custom_target(version ALL "${CMAKE_COMMAND}"
											"-D" "VERSION=${VERSION}"
											"-D" "GIT=${GIT_EXECUTABLE}"
											"-D" "TO=${CMAKE_CURRENT_BINARY_DIR}/version/version.h"
											"-D" "BUILD_REMARK=${BUILD_REMARK}"
											"-P" "${CMAKE_CURRENT_SOURCE_DIR}/src/version.cmake" WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
	else()
		message(STATUS "WARNING: Git was not found!")
		set(VERSION "${VERSION}-unknown")
		configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version/version.h")
		add_custom_target(version ALL)
	endif()
endif()
