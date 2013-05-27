cmake_minimum_required(VERSION 2.6)
project (Redc)

macro(test_CLI var msg)
	if (${var})
		message(STATUS "FOUND CLI ${msg} : ${${var}}")
	else (${var})
		message(FATAL_ERROR "NOT FOUND CLI ${msg}")
	endif (${var})
endmacro(test_CLI)

macro(test_FOUND var msg)
	if (${var})
		message(STATUS "FOUND ${msg} : ${${var}}")
	else (${var})
		message(FATAL_ERROR "NOT FOUND ${msg}")
	endif (${var})
	unset(${var} CACHE)
endmacro(test_FOUND)

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckTypeSize)
#include(FindFLEX)
#include(FindBISON)
include(FindPerl)
include(FindPythonInterp)
include(FindPythonLibs)

set(Redc_VERSION_MAJOR 1)
set(Redc_VERSION_MINOR 8)
set(Redc_RELEASE 1)
set(API_VERSION "${Redc_VERSION_MAJOR}.${Redc_VERSION_MINOR}.${Redc_RELEASE}")
if (NOT ABI_VERSION)
	set(ABI_VERSION 0)
endif()

set(CFLAGS_COMMON "-Wall -Wextra -Wunused -pipe -std=gnu99")
set(CFLAGS_COMMON "${CFLAGS_COMMON} -fPIC")

if (CMAKE_COMPILER_IS_GNUCC)
    MESSAGE("GCC!")
    EXEC_PROGRAM(gcc ARGS --version OUTPUT_VARIABLE CMAKE_C_COMPILER_VERSION)
    set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wno-variadic-macros")
    set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wsequence-point")
    set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wredundant-decls")
    set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wshadow")
    if(CMAKE_C_COMPILER_VERSION MATCHES ".*4\\.[6789].*")
        MESSAGE("GCC >= 4.6")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wcomment")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wmain")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wparentheses")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wfloat-equal")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wunsafe-loop-optimizations")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wmissing-prototypes")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wunused-but-set-parameter")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wunused-but-set-variable")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wframe-larger-than=8192")
        #set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wswitch-enum")
        #set(CFLAGS_COMMON "${CFLAGS_COMMON} -Wconversion")
        #set(CFLAGS_COMMON "${CFLAGS_COMMON} -Winline")
        set(CFLAGS_COMMON "${CFLAGS_COMMON} -finline-limit=8192")
    endif()
endif()

set(CMAKE_C_FLAGS                "${CFLAGS_COMMON} -g -O1")
set(CMAKE_C_FLAGS_DEBUG          "${CFLAGS_COMMON} -g -O0 -fno-inline")
set(CMAKE_C_FLAGS_RELEASE        "${CFLAGS_COMMON} -O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CFLAGS_COMMON} -g -O2 -fno-inline")
set(CMAKE_C_FLAGS_MINSIZEREL     "${CFLAGS_COMMON} -Os")
set(CMAKE_INSTALL_PREFIX "/usr/local")

add_definitions(-DAPI_VERSION="${API_VERSION}")

if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
MESSAGE("DEBUG symbols enabled")
add_definitions(-DHAVE_EXTRA_DEBUG=1)
add_definitions(-DHAVE_EXTRA_ASSERT=1)
add_definitions(-DHAVE_ASSERT_SQLX=1)
add_definitions(-DHAVE_ASSERT_HTTP=1)
add_definitions(-DHAVE_ASSERT_SERVER=1)
add_definitions(-DHAVE_ASSERT_META0=1)
add_definitions(-DHAVE_ASSERT_META1=1)
add_definitions(-DHAVE_ASSERT_UTILS=1)
add_definitions(-DHAVE_ASSERT_HASHSTR=1)
endif()

add_definitions(-D_REENTRANT)
add_definitions(-D_LARGE_FILES)
add_definitions(-D_LARGEFILE_SOURCE)
add_definitions(-D_LARGEFILE64_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DG_ERRORCHECK_MUTEXES)
add_definitions(-DG_DISABLE_DEPRECATED=1)
add_definitions(-DHAVE_SOCKLEN_T)
add_definitions(-DHAVE_LEGACY)

###-------------------------------------------------------------------------###

CHECK_TYPE_SIZE(long SIZEOF_LONG)
message(STATUS "sizeof(long) = ${SIZEOF_LONG}")
if(SIZEOF_LONG EQUAL 8)
	set (LD_LIBDIR "lib64")
else(SIZEOF_LONG EQUAL 8)
	set (LD_LIBDIR "lib")
endif(SIZEOF_LONG EQUAL 8)

if (PREFIX)
	set(CMAKE_INSTALL_PREFIX ${PREFIX})
endif (PREFIX)
message(STATUS "Installation prefix : ${CMAKE_INSTALL_PREFIX}")

###-------------------------------------------------------------------------###

find_package(Doxygen)
if (DOXYGEN_FOUND)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
		${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
add_custom_target(doc
		${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Generating API documentation with Doxygen" VERBATIM)
endif(DOXYGEN_FOUND)

find_package(PkgConfig)
if (PkgConfig_FOUND)
else (PkgConfig_FOUND)
endif (PkgConfig_FOUND)

find_program(BISON_EXECUTABLE bison)
find_program(FLEX_EXECUTABLE flex)
find_program(SED_EXECUTABLE sed)
find_program(CP_EXECUTABLE cp)
test_CLI(CP_EXECUTABLE "cp")
test_CLI(SED_EXECUTABLE "sed")
test_CLI(FLEX_EXECUTABLE "flex")
test_CLI(BISON_EXECUTABLE "bison")
test_CLI(PERL_EXECUTABLE "perl")
test_CLI(PYTHON_EXECUTABLE "python")

if (SSL_LIBDIR AND SSL_INCDIR)
	set(OPENSSL_LIBRARIES "-lcrypto -lssl")
	set(OPENSSL_LIBRARY_DIRS ${SSL_LIBDIR})
	set(OPENSSL_INCLUDE_DIRS ${SSL_INCDIR})
else()
	pkg_check_modules(OPENSSL REQUIRED libssl libcrypto)
endif()

pkg_check_modules(GLIB2 REQUIRED glib-2.0 gthread-2.0 gmodule-2.0)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(NEON REQUIRED neon)
if (NOT CLIENT_ONLY)
pkg_check_modules(LIBEVENT REQUIRED libevent)
pkg_check_modules(APR REQUIRED apr-1)
endif()
pkg_check_modules(DBUS REQUIRED dbus-1 dbus-glib-1)

if (NOT CLIENT_ONLY)
###--------------------###
### Dependency to attr ###
###--------------------###
set(ATTR_INCLUDE_DIRS "/usr/include")
set(ATTR_LIBRARY_DIRS "/${LD_LIBDIR}")
if (ATTR_LIBDIR)
	set(ATTR_LIBRARY_DIRS "${ATTR_LIBDIR}")
endif(ATTR_LIBDIR)
if (ATTR_INCDIR)
	set(ATTR_INCLUDE_DIRS ${ATTR_INCDIR})
endif (ATTR_INCDIR)
### Check for mandatory elements
find_library(FOUND libattr.so ATTR_LIBRARY_DIRS)
test_FOUND(FOUND "libattr library")

###-----------------------------###
### Dependency to apache2-httpd ###
###-----------------------------###
set(APACHE2_INCLUDE_DIRS "/usr/include/httpd")
set(APACHE2_LIBRARY_DIRS "/usr/${LD_LIBDIR}/httpd")
if (APACHE2_INCDIR)
	set(APACHE2_INCLUDE_DIRS "${APACHE2_INCDIR}")
endif (APACHE2_INCDIR)
if (APACHE2_LIBDIR)
	set(APACHE2_LIBRARY_DIRS "${APACHE2_LIBDIR}")
endif (APACHE2_LIBDIR)
### Check for mandatory elements
find_file(FOUND NAMES httpd/httpd.h httpd.h PATHS ${APACHE2_INCLUDE_DIRS})
test_FOUND(FOUND "apache2-httpd header")

###--------------------###
### Dependency to zlib ###
###--------------------###
set(ZLIB_INCLUDE_DIRS "/usr/include")
set(ZLIB_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (ZLIB_INCDIR)
	set(ZLIB_INCLUDE_DIRS "${ZLIB_INCDIR}")
endif (ZLIB_INCDIR)
if (ZLIB_LIBDIR)
	set(ZLIB_LIBRARY_DIRS "${ZLIB_LIBDIR}")
endif(ZLIB_LIBDIR)
### Check the mandatory elements
find_library(FOUND libz.so ${ZLIB_LIBRARY_DIRS})
test_FOUND(FOUND "Zlib library")
find_file(FOUND zlib.h ${ZLIB_INCLUDE_DIRS})
test_FOUND(FOUND "Zlib header")

###-------------------###
### Dependency to lzo ###
###-------------------###
set(LZO_INCLUDE_DIRS "/usr/include/lzo")
set(LZO_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (LZO_INCDIR)
	set(LZO_INCLUDE_DIRS "${LZO_INCDIR}")
endif (LZO_INCDIR)
if (LZO_LIBDIR)
	set(LZO_LIBRARY_DIRS "${LZO_LIBDIR}")
endif (LZO_LIBDIR)
### Check for mandatory elements
find_library(FOUND liblzo2.so ${LZO_LIBRARY_DIRS})
test_FOUND(FOUND "lzo library")
find_file(FOUND lzo1.h ${LZO_INCLUDE_DIRS})
test_FOUND(FOUND "lzo1.h header")
find_file(FOUND lzo1x.h ${LZO_INCLUDE_DIRS})
test_FOUND(FOUND "lzo1x.h header")
find_file(FOUND lzoutil.h ${LZO_INCLUDE_DIRS})
test_FOUND(FOUND "lzoutil.h header")

###------------------------###
### Dependency to gridinit ###
###------------------------###
set(GRIDINIT_INCLUDE_DIRS "/usr/local/include")
set(GRIDINIT_LIBRARY_DIRS "/usr/local/${LD_LIBDIR}")
if (GRIDINIT_INCDIR)
	set(GRIDINIT_INCLUDE_DIRS "${GRIDINIT_INCDIR}")
endif (GRIDINIT_INCDIR)
if (GRIDINIT_LIBDIR)
	set(GRIDINIT_LIBRARY_DIRS "${GRIDINIT_LIBDIR}")
endif (GRIDINIT_LIBDIR)
find_file(FOUND gridinit-utils.h ${GRIDINIT_INCLUDE_DIRS})
test_FOUND(FOUND "gridinit header")
find_library(FOUND libgridinit-utils.so ${GRIDINIT_LIBRARY_DIRS})
test_FOUND(FOUND "gridinit library")

###------------------------###
### Dependency to Net-SNMP ###
###------------------------###
set(NETSNMP_INCLUDE_DIRS "/usr/include")
set(NETSNMP_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (NETSNMP_INCDIR)
	set(NETSNMP_INCLUDE_DIRS ${NETSNMP_INCDIR})
endif(NETSNMP_INCDIR)
if(NETSNMP_LIBDIR)
	set(NETSNMP_LIBRARY_DIRS ${NETSNMP_LIBDIR})
endif(NETSNMP_LIBDIR)
### Check for the mandatory elements
find_library(FOUND libnetsnmp.so ${NETSNMP_LIBRARY_DIRS})
test_FOUND(FOUND "Net-SNMP library")
find_file(FOUND net-snmp/agent/net-snmp-agent-includes.h ${NETSNMP_INCLUDE_DIRS})
test_FOUND(FOUND "Net-SNMP header")
find_file(FOUND net-snmp/net-snmp-includes.h ${NETSNMP_INCLUDE_DIRS})
test_FOUND(FOUND "Net-SNMP header")
find_file(FOUND net-snmp/net-snmp-config.h ${NETSNMP_INCLUDE_DIRS})
test_FOUND(FOUND "Net-SNMP header")

###-------------------------###
### Dependency to Zookeeper ###
###-------------------------###
set(ZK_INCLUDE_DIRS "/usr/include/zookeeper")
set(ZK_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (ZK_INCDIR)
	set(ZK_INCLUDE_DIRS ${ZK_INCDIR})
endif(ZK_INCDIR)
if(ZK_LIBDIR)
	set(ZK_LIBRARY_DIRS ${ZK_LIBDIR})
endif(ZK_LIBDIR)
find_file(FOUND zookeeper/zookeeper.h ${ZK_INCLUDE_DIRS})
test_FOUND(FOUND "Zookeeper client header")
find_library(FOUND libzookeeper_mt.so ${ZK_LIBRARY_DIRS})
test_FOUND(FOUND "Zookeeper client library")

###---------------------###
### Dependency to ASN1c ###
###---------------------###
if (ASN1C_EXE)
	set(ASN1C_EXECUTABLE ${ASN1C_EXE})
else()
	find_program(ASN1C_EXECUTABLE asn1c)
endif()
message("asn1c at ${ASN1C_EXECUTABLE}")

set(ASN1C_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if(ASN1C_LIBDIR)
	set(ASN1C_LIBRARY_DIRS ${ASN1C_LIBDIR})
endif(ASN1C_LIBDIR)

find_library(FOUND libASN1.so ${ASN1C_LIBRARY_DIRS})
test_FOUND(FOUND "asn1c base codec library")

endif()

###---------------------------------------------###
### explicit plugin directory for gridd modules ###
###---------------------------------------------###
set(GRIDD_PLUGINS_DIRECTORY "${LD_LIBDIR}/grid")
if(GRIDD_PLUGINS)
	set(GRIDD_PLUGINS_DIRECTORY "${GRIDD_PLUGINS}")
endif(GRIDD_PLUGINS)

###-------------------------------------------------------------------------###

set(CMAKE_LIBRARY_PATH "")
set(CMAKE_INCLUDE_PATH "")
include_directories(AFTER
		${GLIB2_INCLUDE_DIRS})

link_directories(
		${OPENSSL_LIBRARY_DIRS}
		${GLIB2_LIBRARY_DIRS}
		${ASN1C_LIBRARY_DIRS})

ENABLE_TESTING()

add_subdirectory(./metautils/lib)
add_subdirectory(./server)
add_subdirectory(./sqliterepo)

if(NOT CLIENT_ONLY)
	add_subdirectory(./sqlx)
endif()

add_subdirectory(./cluster/events)
add_subdirectory(./cluster/remote)
add_subdirectory(./cluster/lib)

if(NOT CLIENT_ONLY)
	add_subdirectory(./cluster/conscience)
	add_subdirectory(./cluster/agent)
endif()

add_subdirectory(./cluster/tools)
add_subdirectory(./meta2/remote)

add_subdirectory(./gridd/main)
add_subdirectory(./gridd/clients/ping)
add_subdirectory(./gridd/clients/stats)

add_subdirectory(./gridd/plugins/msg_fallback)
add_subdirectory(./gridd/plugins/msg_ping)
add_subdirectory(./gridd/plugins/msg_stats)

if(NOT CLIENT_ONLY)
	add_subdirectory(./gridd/plugins/acl)
	add_subdirectory(./cluster/module)
	add_subdirectory(./cluster/event_service)
	add_subdirectory(./meta2v2)
	add_subdirectory(./rawx-client/lib)
endif()

add_subdirectory(./meta0v2)
add_subdirectory(./meta1v2)
add_subdirectory(./resolver)
add_subdirectory(./client/c/lib2)
add_subdirectory(./client/c/lib)
add_subdirectory(./client/c/metacd_module)
add_subdirectory(./client/c/tools)
add_subdirectory(./client/c/bench)

if (NOT CLIENT_ONLY)
	add_subdirectory(./rawx-lib/src)
	add_subdirectory(./rawx-lib/tools)
	add_subdirectory(./rawx-mover/src)
	add_subdirectory(./rawx-monitor/src)
	add_subdirectory(./rawx-apache2/src)

	add_subdirectory(./meta2-mover/lib)
	add_subdirectory(./meta2-mover/tools)

	if (PYTHONLIBS_FOUND)
		add_subdirectory(./rules-motor/lib)
	endif()

	add_subdirectory(./integrity/lib)
	add_subdirectory(./integrity/tools)
	add_subdirectory(./snmp/src)

	add_subdirectory(./vns-agent/lib)
	add_subdirectory(./vns-agent/remote)
	add_subdirectory(./vns-agent/module)
	add_subdirectory(./tools)
endif()

add_subdirectory(./crawler)
