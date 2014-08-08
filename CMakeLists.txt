cmake_minimum_required(VERSION 2.6)
project (Grid)

macro(test_CLI var msg)
	if (${var})
		MESSAGE(STATUS "FOUND CLI ${msg} : ${${var}}")
	else (${var})
		MESSAGE(FATAL_ERROR "NOT FOUND CLI ${msg}")
	endif (${var})
endmacro(test_CLI)

macro(test_FOUND var msg)
	if (${var})
		MESSAGE(STATUS "FOUND ${msg} : ${${var}}")
	else (${var})
		MESSAGE(FATAL_ERROR "NOT FOUND ${msg}")
	endif (${var})
	unset(${var} CACHE)
endmacro(test_FOUND)

macro(bin_prefix T N)
	if (DEFINED EXE_PREFIX)
	set_target_properties(${T} PROPERTIES OUTPUT_NAME ${EXE_PREFIX}${N})
	endif()
endmacro(bin_prefix)

macro(bin_prefix_full T N)
	if (DEFINED FULL_RENAME)
	if (DEFINED EXE_PREFIX)
	set_target_properties(${T} PROPERTIES OUTPUT_NAME ${EXE_PREFIX}${N})
	endif()
	endif()
endmacro(bin_prefix_full)

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckTypeSize)
#include(FindFLEX)
#include(FindBISON)
include(FindCURL)
include(FindPerl)
include(FindPythonInterp)
include(FindPythonLibs)

set(Grid_VERSION_MAJOR 1)
set(Grid_VERSION_MINOR 8)
set(Grid_RELEASE 4)
set(API_VERSION "${Grid_VERSION_MAJOR}.${Grid_VERSION_MINOR}.${Grid_RELEASE}")
set(SHORT_API_VERSION "${Grid_VERSION_MAJOR}.${Grid_VERSION_MINOR}")
if (NOT ABI_VERSION)
	set(ABI_VERSION 0)
endif()

set(CMAKE_C_FLAGS "-g -fPIC -pipe -Wall -Wextra -std=gnu99")

if (CMAKE_COMPILER_IS_GNUCC)
    EXEC_PROGRAM(gcc ARGS --version OUTPUT_VARIABLE CMAKE_C_COMPILER_VERSION)

	# Activates the stack protection code when explicitely triggered
	# and with a decently recent gcc (>= 4.2)
    if(CMAKE_C_COMPILER_VERSION MATCHES " [4-9]\\.[2-9]\\.[0-9]+")
		if (STACK_PROTECTOR)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
		endif()
	endif()

	# Activates extra warnings that are available in recents gcc.
	# Some appeared well-managed since 4.4, others since 4.6.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-variadic-macros")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsequence-point")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wredundant-decls")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")

    if(CMAKE_C_COMPILER_VERSION MATCHES " [4-9]\\.[4-9]\\.[0-9]+")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcomment")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmain")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wparentheses")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfloat-equal")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunsafe-loop-optimizations")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-parameter")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-variable")
    endif()

	if(CMAKE_C_COMPILER_VERSION MATCHES " [4-9]\\.[6-9]\\.[0-9]+")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
		#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
		#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-enum")
	endif()
endif()

set(CMAKE_C_FLAGS_DEBUG          "-O0 -fno-inline")
set(CMAKE_C_FLAGS_RELEASE        "-O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -fno-inline")
set(CMAKE_C_FLAGS_MINSIZEREL     "-Os -s")
set(CMAKE_INSTALL_PREFIX "/usr/local")

add_definitions(-DAPI_VERSION="${API_VERSION}")
add_definitions(-DSHORT_API_VERSION="${SHORT_API_VERSION}")

if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
MESSAGE("DEBUG symbols enabled")
add_definitions(-DHAVE_EXTRA_ASSERT=1)
add_definitions(-DHAVE_ASSERT_EXTRA=1)
add_definitions(-DHAVE_EXTRA_DEBUG=1)
add_definitions(-DHAVE_DEBUG_EXTRA=1)
endif()

if (DEFINED MOCKS)
	MESSAGE("MOCKS enabled ${MOCKS}")
	add_definitions(-DHAVE_MOCKS)
endif()
if (DEFINED SOCKET_OPTIMIZED)
	MESSAGE("SOCKET_OPTIMIZED ${SOCKET_OPTIMIZED}")
	add_definitions(-D_GNU_SOURCE)
	add_definitions(-DHAVE_SOCKET3)
	add_definitions(-DHAVE_ACCEPT4)
endif()

if (DEFINED SOCKET_LINGER_ONOFF)
	MESSAGE("SOCKET_LINGER_ONOFF ${SOCKET_LINGER_ONOFF}")
	add_definitions(-DSOCK_DEFAULT_LINGER_ONOFF=${SOCKET_LINGER_ONOFF})
endif ()

if (DEFINED SOCKET_LINGER_DELAY)
	MESSAGE("SOCKET_LINGER_DELAY ${SOCKET_LINGER_DELAY}")
	add_definitions(-DSOCK_DEFAULT_LINGER_DELAY=${SOCKET_LINGER_DELAY})
endif ()

add_definitions(-D_REENTRANT)
add_definitions(-D_LARGE_FILES)
add_definitions(-D_LARGEFILE_SOURCE)
add_definitions(-D_LARGEFILE64_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DG_ERRORCHECK_MUTEXES)
add_definitions(-DHAVE_SOCKLEN_T)

if (DEFINED ALLOW_DEPRECATED)
	if (ALLOW_DEPRECATED)
		#add_definitions(-DG_DISABLE_DEPRECATED=1)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
	endif ()
endif ()


###-------------------------------------------------------------------------###

if (LD_LIBDIR)
	MESSAGE("LD_LIBDIR explicitely set to ${LD_LIBDIR}")
else()
	CHECK_TYPE_SIZE(long SIZEOF_LONG)
	MESSAGE(STATUS "sizeof(long) = ${SIZEOF_LONG}")
	if(SIZEOF_LONG EQUAL 8)
		set (LD_LIBDIR "lib64")
	else(SIZEOF_LONG EQUAL 8)
		set (LD_LIBDIR "lib")
	endif(SIZEOF_LONG EQUAL 8)
endif()

if (PREFIX)
	set(CMAKE_INSTALL_PREFIX ${PREFIX})
endif (PREFIX)
MESSAGE(STATUS "Installation prefix : ${CMAKE_INSTALL_PREFIX}")

set(TRIP_INSTALL_PATH "${PREFIX}/${LD_LIBDIR}/grid")
if (TRIP_PATH)
	set(TRIP_INSTALL_PATH ${TRIP_PATH})
endif (TRIP_PATH)
message(STATUS "Trip lib location path : ${TRIP_INSTALL_PATH}")

add_definitions(-DTRIP_INSTALL_PATH="${TRIP_INSTALL_PATH}")

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
	if (NOT DEFINED ZMQ_INCDIR)
		pkg_check_modules(ZMQ libzmq>=3.0.0)
	endif()
pkg_check_modules(JSONC json)
pkg_check_modules(JSONC json-c)
pkg_check_modules(LIBEVENT REQUIRED libevent)
pkg_check_modules(APR REQUIRED apr-1)
pkg_check_modules(GAMIN REQUIRED gamin)
pkg_check_modules(DBUS REQUIRED dbus-1 dbus-glib-1)
pkg_check_modules(RDKAFKA rdkafka)
endif()

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
find_file(FOUND httpd.h PATHS ${APACHE2_INCLUDE_DIRS})
test_FOUND(FOUND "apache2-httpd header")

###------------------------###
### Dependency to lighttpd ###
###------------------------###
set(LIGHTTPD_INCLUDE_DIRS "/usr/include")
set(LIGHTTPD_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (LIGHTTPD_INCDIR)
	set(LIGHTTPD_INCLUDE_DIRS "${LIGHTTPD_INCDIR}")
endif(LIGHTTPD_INCDIR)
if (LIGHTTPD_LIBDIR)
	set(LIGHTTPD_LIBRARY_DIRS "${LIGHTTPD_LIBDIR}")
endif(LIGHTTPD_LIBDIR)
### Check for mandatory elements
find_file(FOUND0 lighttpd/base.h ${LIGHTTPD_INCLUDE_DIRS})
find_library(FOUND1 lighttpd/mod_expire.so ${LIGHTTPD_LIBRARY_DIRS})
set(LIGHTTPD_FOUND FALSE)
if (FOUND0 AND FOUND1)
	set(LIGHTTPD_FOUND TRUE)
else()
	MESSAGE(STATUS "NOT FOUND lighttpd")
endif()

###--------------------------###
### Dependency to BerkeleyDB ###
###--------------------------###
set(DB_INCLUDE_DIRS "/usr/include")
set(DB_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (DB_INCDIR)
	set(DB_INCLUDE_DIRS "${DB_INCDIR}")
endif(DB_INCDIR)
if (DB_LIBDIR)
	set(DB_LIBRARY_DIRS "${DB_LIBDIR}")
endif(DB_LIBDIR)
### Check for mandatory elements
find_library(FOUND libdb.so ${DB_LIBRARY_DIRS})
test_FOUND(FOUND "Berkeley DB library")
find_file(FOUND db.h ${DB_INCLUDE_DIRS})
test_FOUND(FOUND "Berkeley DB header")

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
### Dependency to librain  ###
###------------------------###
set(LIBRAIN_INCLUDE_DIRS "/usr/local/include")
set(LIBRAIN_LIBRARY_DIRS "/usr/local/${LD_LIBDIR}")
if (LIBRAIN_INCDIR)
	set(LIBRAIN_INCLUDE_DIRS "${LIBRAIN_INCDIR}")
endif (LIBRAIN_INCDIR)
if (LIBRAIN_LIBDIR)
	set(LIBRAIN_LIBRARY_DIRS "${LIBRAIN_LIBDIR}")
endif (LIBRAIN_LIBDIR)
find_file(FOUND librain.h ${LIBRAIN_INCLUDE_DIRS})
test_FOUND(FOUND "librain header")
find_library(FOUND librain.so ${LIBRAIN_LIBRARY_DIRS})
test_FOUND(FOUND "librain library")

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

#	###---------------------###
#	### Dependency to JSONC ###
#	###---------------------###
#	set(JSONC_INCLUDE_DIRS "/usr/include")
#	set(JSONC_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
#	if (JSONC_INCDIR)
#		set(JSONC_INCLUDE_DIRS ${JSONC_INCDIR})
#	endif()
#	if(JSONC_LIBDIR)
#		set(JSONC_LIBRARY_DIRS ${JSONC_LIBDIR})
#	endif()
#	find_file(FOUND json/json.h ${JSONC_INCLUDE_DIRS})
#	test_FOUND(FOUND "json-c client header")
#	find_library(FOUND libjson.so ${JSONC_LIBRARY_DIRS})
#	test_FOUND(FOUND "json-c client library")

###---------------------###
### Dependency to ASN1c ###
###---------------------###
if (ASN1C_EXE)
	set(ASN1C_EXECUTABLE ${ASN1C_EXE})
else()
	find_program(ASN1C_EXECUTABLE asn1c)
endif()
MESSAGE("asn1c at ${ASN1C_EXECUTABLE}")

set(ASN1C_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if(ASN1C_LIBDIR)
	set(ASN1C_LIBRARY_DIRS ${ASN1C_LIBDIR})
endif(ASN1C_LIBDIR)

find_library(FOUND libASN1.so ${ASN1C_LIBRARY_DIRS})
test_FOUND(FOUND "asn1c base codec library")

###----------------------###
### Dependency to ZeroMQ ###
###----------------------###
set(ZMQ_INCLUDE_DIRS "/usr/include")
set(ZMQ_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
if (ZMQ_INCDIR)
	set(ZMQ_INCLUDE_DIRS ${ZMQ_INCDIR})
	set(ZMQ_FOUND ON)
endif()
if(ZMQ_LIBDIR)
	set(ZMQ_LIBRARY_DIRS ${ZMQ_LIBDIR})
	set(ZMQ_FOUND ON)
endif()

find_file(FOUND zmq_utils.h ${ZMQ_INCLUDE_DIRS})
if (NOT FOUND)
	set(ZMQ_FOUND OFF)
endif()

find_file(FOUND zmq.h ${ZMQ_INCLUDE_DIRS})
if (NOT FOUND)
	set(ZMQ_FOUND OFF)
endif()

find_library(ZMQ_LIBRARIES libzmq.so ${ZMQ_LIBRARY_DIRS})
if (NOT ZMQ_LIBRARIES)
	set(ZMQ_FOUND OFF)
endif()

endif()

###-----------------------------###
### Dependency to libmicrohttpd ###
###-----------------------------###

set(MICROHTTPD_INCLUDE_DIRS "/usr/include")
set(MICROHTTPD_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
set(MHD_FOUND ON)
unset(FOUND CACHE)
find_file(FOUND microhttpd.h ${MICROHTTPD_INCLUDE_DIRS})
if (NOT FOUND)
	set(MHD_FOUND OFF)
endif(NOT FOUND)

unset(FOUND CACHE)
find_library(FOUND libmicrohttpd.so ${MICROHTTPD_LIBRARY_DIRS})
if (NOT FOUND)
	set(MHD_FOUND OFF)
endif(NOT FOUND)

if (MHD_FOUND)
	message(STATUS "FOUND libmicrohttpd")
else(MHD_FOUND)
	message(STATUS "NOT FOUND libmicrohttpd (required for some unit tests)")
endif(MHD_FOUND)


###---------------------------------------------###
### explicit plugin directory for gridd modules ###
###---------------------------------------------###
set(GRIDD_PLUGINS_DIRECTORY "${LD_LIBDIR}/grid")
if(GRIDD_PLUGINS)
	set(GRIDD_PLUGINS_DIRECTORY "${GRIDD_PLUGINS}")
endif(GRIDD_PLUGINS)

###-------------------------------------------------------------------------###

MESSAGE(STATUS "ZMQ     (${ZMQ_FOUND}? ${ZMQ_VERSION})")
MESSAGE(STATUS "JSONC   (${JSONC_FOUND}? ${JSONC_VERSION})")
MESSAGE(STATUS "GLIB2   (${GLIB2_FOUND}? ${GLIB2_VERSION})")
MESSAGE(STATUS "RDKAFKA (${RDKAFKA_FOUND}? ${RDKAFKA_VERSION})")


set(CMAKE_LIBRARY_PATH "")
set(CMAKE_INCLUDE_PATH "")
include_directories(AFTER
		${GLIB2_INCLUDE_DIRS})

link_directories(
		${OPENSSL_LIBRARY_DIRS}
		${GLIB2_LIBRARY_DIRS}
		${ASN1C_LIBRARY_DIRS}
		${LIBRAIN_LIBRARY_DIRS})

ENABLE_TESTING()

add_subdirectory(./metautils/lib)
add_subdirectory(./server)
add_subdirectory(./sqliterepo)
add_subdirectory(./cluster/events)
add_subdirectory(./cluster/remote)
add_subdirectory(./cluster/lib)
add_subdirectory(./cluster/tools)
add_subdirectory(./meta2/remote)
add_subdirectory(./gridd/main)
add_subdirectory(./gridd/clients/ping)
add_subdirectory(./gridd/clients/stats)
add_subdirectory(./gridd/plugins/msg_fallback)
add_subdirectory(./gridd/plugins/msg_ping)
add_subdirectory(./gridd/plugins/msg_stats)
add_subdirectory(./gridd/plugins/acl)
add_subdirectory(./meta0v2)
add_subdirectory(./meta1v2)
add_subdirectory(./resolver)
add_subdirectory(./client/c/lib)
add_subdirectory(./client/c/metacd_module)
add_subdirectory(./client/c/tools)

if(NOT CLIENT_ONLY)
	add_subdirectory(./cluster/conscience)
	add_subdirectory(./cluster/agent)
	add_subdirectory(./cluster/module)
	add_subdirectory(./sqlx)
	add_subdirectory(./meta2v2)
	add_subdirectory(./rawx-client/lib)
	add_subdirectory(./rawx-lib/src)
	add_subdirectory(./rawx-lib/tools)
	add_subdirectory(./rawx-mover/src)
	add_subdirectory(./rawx-monitor/src)
	add_subdirectory(./rawx-apache2/src)
	add_subdirectory(./rainx)
	add_subdirectory(./polix)
	add_subdirectory(./meta2-mover/lib)
	add_subdirectory(./meta2-mover/tools)
	add_subdirectory(./integrity/lib)
	add_subdirectory(./integrity/tools)
	add_subdirectory(./snmp/src)
	add_subdirectory(./svc-monitor/src)
	add_subdirectory(./svc-monitor/contrib)
	add_subdirectory(./vns-agent/lib)
	add_subdirectory(./vns-agent/remote)
	add_subdirectory(./vns-agent/module)
	add_subdirectory(./tools)
	if (PYTHONLIBS_FOUND)
		add_subdirectory(./rules-motor/lib)
	endif()
	if (ZMQ_FOUND)
		if (JSONC_FOUND)
			add_subdirectory(./crawler/lib)
			add_subdirectory(./crawler)
			add_subdirectory(./crawler/listener)
		endif()
	endif()
endif()

