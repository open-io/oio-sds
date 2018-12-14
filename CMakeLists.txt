cmake_minimum_required(VERSION 2.8)
project (OIOSDS C)

option(ENBUG "Introduces intentional bugs" OFF)
option(STACK_PROTECTOR "Instrument the code to detect stack smashings" OFF)
option(SOCKET_OPTIMIZED "Use Linux specific functions to save syscalls" ON)
option(ALLOW_BACKTRACE "Attempt to compute backtraces when errors occur" OFF)
option(FORBID_DEPRECATED "Avoid the deprecated symbols of the GLib2" OFF)
option(ENABLE_CODECOVERAGE "Enable code coverage testing support" OFF)

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckTypeSize)
include(FindFLEX)
include(FindBISON)
#include(FindCURL)
include(FindPythonInterp)
include(FindZLIB)
find_package(PkgConfig)

if (NOT DEFINED OIOSDS_RELEASE)
	set(OIOSDS_RELEASE master)
endif ()
if (NOT DEFINED OIOSDS_PROJECT_VERSION_SHORT)
	set(OIOSDS_PROJECT_VERSION_SHORT "4.3")
endif ()

set(OIOSDS_PROJECT_VERSION "${OIOSDS_RELEASE}/${OIOSDS_PROJECT_VERSION_SHORT}")

if (NOT ABI_VERSION)
	set(ABI_VERSION 0)
endif()

set(CMAKE_C_FLAGS "-g -fPIC -pipe -Wall -Wextra -std=gnu99")
set(PYTHON python)

# necessary to benefit from zero'ed static allocation of structures
# as proposed by C99. (we only allocate the first field and let the compiler
# init the others to zero.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")

if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-variadic-macros")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsequence-point")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wredundant-decls")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")

	# gcc >= 4.2
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcomment")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmain")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wparentheses")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfloat-equal")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunsafe-loop-optimizations")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-parameter")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-variable")

	# gcc >= 4.6
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-enum")
endif()

if ( ENABLE_CODECOVERAGE )

    if ( NOT DEFINED CODECOV_OUTPUTFILE )
        set( CODECOV_OUTPUTFILE cmake_coverage.output )
    endif ( NOT DEFINED CODECOV_OUTPUTFILE )

    if ( NOT DEFINED CODECOV_HTMLOUTPUTDIR )
        set( CODECOV_HTMLOUTPUTDIR coverage_results )
    endif ( NOT DEFINED CODECOV_HTMLOUTPUTDIR )


	set(CODECOV_PATTERN_TO_IGNORE
		"'${CMAKE_BINARY_DIR}/metautils/asn1c/*.*'"
		"'metautils/asn1c/*.*'")

    set(PYTHON_COVERAGE_FILE ${CMAKE_BINARY_DIR}/.python_coverage)
    set(PYTHON coverage run -p --source=${CMAKE_SOURCE_DIR})

    if ( CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX )
        find_program( CODECOV_GCOV gcov )
        find_program( CODECOV_LCOV lcov )
        find_program( CODECOV_GENHTML genhtml )
        add_definitions( -fprofile-arcs -ftest-coverage )
        link_libraries( gcov )
        set( CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} --coverage )

        add_custom_target( coverage_init
                           ${CODECOV_LCOV} --base-directory ${CMAKE_SOURCE_DIR}  --directory ${CMAKE_BINARY_DIR} --output-file ${CODECOV_OUTPUTFILE} --capture --initial
                           COMMAND coverage erase)

        add_custom_target( coverage
						   ${CODECOV_LCOV} --base-directory ${CMAKE_SOURCE_DIR}  --directory ${CMAKE_BINARY_DIR} --no-external --output-file ${CODECOV_OUTPUTFILE} --capture
                           COMMAND ${CODECOV_LCOV} --output ${CODECOV_OUTPUTFILE} --remove ${CODECOV_OUTPUTFILE} ${CODECOV_PATTERN_TO_IGNORE}
						   COMMAND genhtml --ignore-errors source -o ${CODECOV_HTMLOUTPUTDIR} ${CODECOV_OUTPUTFILE}
                           COMMAND coverage combine
                           COMMAND coverage html)

    endif ( CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX )
endif (ENABLE_CODECOVERAGE )

set(CMAKE_C_FLAGS_DEBUG          "-O0 -fno-inline")
set(CMAKE_C_FLAGS_RELEASE        "-O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -fno-inline")
set(CMAKE_C_FLAGS_MINSIZEREL     "-Os -s")

add_definitions(-D_REENTRANT)
add_definitions(-D_LARGE_FILES)
add_definitions(-D_LARGEFILE_SOURCE)
add_definitions(-D_LARGEFILE64_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DHAVE_SOCKLEN_T)
add_definitions(-DOIOSDS_PROJECT_VERSION="${OIOSDS_PROJECT_VERSION}")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_definitions(-DG_ERRORCHECK_MUTEXES)
	add_definitions(-DHAVE_EXTRA_ASSERT=1)
	add_definitions(-DHAVE_EXTRA_DEBUG=1)
endif()

MESSAGE("OPTIONS:"
	" ENBUG=${ENBUG}"
	" SOCKET_OPTIMIZED=${SOCKET_OPTIMIZED}"
	" FORBID_SLICE=${FORBID_SLICE}"
	" STACK_PROTECTOR=${STACK_PROTECTOR}"
	" FORBID_DEPRECATED=${FORBID_DEPRECATED}"
	" ALLOW_BACKTRACE=${ALLOW_BACKTRACE}"
	" ENABLE_CODECOVERAGE=${ENABLE_CODECOVERAGE}")

if (ENBUG)
	MESSAGE(WARNING "ENBUGED MODE : NOT FOR PRODUCTION USE")
	add_definitions(-DHAVE_ENBUG=1)
endif()

if (STACK_PROTECTOR)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
endif()

if (SOCKET_OPTIMIZED)
	add_definitions(-D_GNU_SOURCE)
	add_definitions(-DHAVE_SOCKET3)
	add_definitions(-DHAVE_ACCEPT4)
endif()

if (ALLOW_BACKTRACE)
	add_definitions(-DHAVE_BACKTRACE)
endif()


if (FORBID_DEPRECATED)
	add_definitions(-DG_DISABLE_DEPRECATED=1)
endif ()

###-------------------------------------------------------------------------###

macro (dir2macro N)
	if (${N})
		add_definitions(-D${N}=${${N}})
		MESSAGE("CFLAGS: ${N} = ${${N}}")
	endif ()
endmacro ()

macro(test_CLI var msg)
	if (${var})
		MESSAGE(STATUS "FOUND CLI ${msg} : ${${var}}")
	else ()
		MESSAGE(FATAL_ERROR "NOT FOUND CLI ${msg}")
	endif ()
endmacro()

function (print_found arg)
	MESSAGE (STATUS "### ${arg} F=${${arg}_FOUND} V=${${arg}_VERSION} I=${${arg}_INCLUDE_DIRS} LD=${${arg}_LIBRARY_DIRS} L=${${arg}_LIBRARIES} H=${${arg}_HEADER}")
endfunction()

function (check_found)
	foreach (arg ${ARGN})
		print_found (${arg})
	endforeach()
	foreach (arg ${ARGN})
		if (NOT ${arg}_FOUND)
			MESSAGE(FATAL_ERROR " ${arg} not found")
		endif ()
	endforeach ()
endfunction()

macro (option_or_system _PREFIX _LIB)

	# Set configured defaults
	if (NOT DEFINED ${_PREFIX}_INCLUDE_DIRS)
		set (${_PREFIX}_INCLUDE_DIRS "${DEFAULT_INCLUDE_DIRS}" )
	endif ()
	if (NOT DEFINED ${_PREFIX}_LIBRARY_DIRS)
		set (${_PREFIX}_LIBRARY_DIRS "${DEFAULT_LIBRARY_DIRS}" )
	endif ()

	# Override with CLI options
	if (DEFINED ${_PREFIX}_INCDIR)
		set (${_PREFIX}_INCLUDE_DIRS ${${_PREFIX}_INCDIR} )
	endif ()
	if (DEFINED ${_PREFIX}_LIBDIR)
		set (${_PREFIX}_LIBRARY_DIRS ${${_PREFIX}_LIBDIR} )
	endif ()

	# Check expected elements are present
	find_library (${_PREFIX}_LIBRARIES ${_LIB} PATHS ${${_PREFIX}_LIBRARY_DIRS})
	set (_FOUND true)
	set (_HEADERS "")
	foreach (arg ${ARGN})
		if (_FOUND)
			find_file (_HEADER ${arg} ${${_PREFIX}_INCLUDE_DIRS})
			if (NOT _HEADER OR _HEADER MATCHES ".*NOTFOUND$")
				set (_FOUND false)
			else ()
				set (_HEADERS "${_HEADERS}:${_HEADER}")
			endif ()
			unset(_HEADER CACHE)
		endif ()
	endforeach ()

	if (NOT ${_PREFIX}_LIBRARIES OR ${_PREFIX}_LIBRARIES MATCHES ".*NOTFOUND$")
		set (${_PREFIX}_FOUND true )
	endif ()
	set (${_PREFIX}_FOUND ${_FOUND})
	set (${_PREFIX}_HEADER "${_HEADERS}")
	unset(_FOUND CACHE)
	unset(_HEADERS CACHE)
endmacro ()

macro(bin_prefix T N)
	set_target_properties(${T} PROPERTIES OUTPUT_NAME "oio${N}")
endmacro ()

###-------------------------------------------------------------------------###

dir2macro("GCLUSTER_RUN_DIR")
dir2macro("GCLUSTER_ETC_DIR")

dir2macro("GCLUSTER_CONFIG_FILE_PATH")
dir2macro("GCLUSTER_CONFIG_DIR_PATH")
dir2macro("GCLUSTER_CONFIG_LOCAL_PATH")
dir2macro("GCLUSTER_AGENT_SOCK_PATH")

dir2macro("OIO_EVT_BEANSTALKD_DEFAULT_TUBE")

dir2macro("OIO_ETC_DIR")
dir2macro("OIO_CONFIG_FILE_PATH")
dir2macro("OIO_CONFIG_DIR_PATH")
dir2macro("OIO_CONFIG_LOCAL_PATH")
dir2macro("OIO_DEFAULT_STGPOL")
dir2macro("OIO_DEFAULT_CHUNKMETHOD")
dir2macro("OIO_DEFAULT_MIMETYPE")

dir2macro("PROXYD_PREFIX")
dir2macro("PROXYD_HEADER_PREFIX")
dir2macro("PROXYD_HEADER_MODE")
dir2macro("PROXYD_HEADER_REQID")
dir2macro("PROXYD_HEADER_NOEMPTY")

dir2macro("SQLX_DIR_SCHEMAS")
dir2macro("SQLX_ADMIN_PREFIX_SYS")
dir2macro("SQLX_ADMIN_PREFIX_USER")
dir2macro("SQLX_ADMIN_INITFLAG")
dir2macro("SQLX_ADMIN_STATUS")
dir2macro("SQLX_ADMIN_REFERENCE")
dir2macro("SQLX_ADMIN_BASENAME")
dir2macro("SQLX_ADMIN_BASETYPE")
dir2macro("SQLX_ADMIN_NAMESPACE")

dir2macro("M2V2_ADMIN_PREFIX_SYS")
dir2macro("M2V2_ADMIN_PREFIX_USER")
dir2macro("M2V2_ADMIN_VERSION")
dir2macro("M2V2_ADMIN_QUOTA")
dir2macro("M2V2_ADMIN_SIZE")
dir2macro("M2V2_ADMIN_CTIME")
dir2macro("M2V2_ADMIN_VERSIONING_POLICY")
dir2macro("M2V2_ADMIN_STORAGE_POLICY")
dir2macro("M2V2_ADMIN_KEEP_DELETED_DELAY")

dir2macro("META2_INIT_FLAG")

dir2macro("DAEMON_DEFAULT_TIMEOUT_READ")
dir2macro("DAEMON_DEFAULT_TIMEOUT_ACCEPT")

dir2macro("OIO_USE_OLD_FMEMOPEN")

include(Variables.CMakeFile)

###-------------------------------------------------------------------------###

if (NOT DEFINED CMAKE_INSTALL_PREFIX)
	set (CMAKE_INSTALL_PREFIX "/usr/local")
endif ()
MESSAGE(STATUS "Installation prefix : ${CMAKE_INSTALL_PREFIX}")


if (LD_LIBEXECDIR)
	MESSAGE("LD_LIBEXECDIR explicitely set to ${LD_LIBEXECDIR}")
else ()
	set (LD_LIBEXECDIR "libexec")
	MESSAGE("LD_LIBEXECDIR set to ${LD_LIBEXECDIR} (default)")
endif ()

if (LD_LIBDIR)
	MESSAGE("LD_LIBDIR explicitely set to ${LD_LIBDIR}")
else()
	CHECK_TYPE_SIZE(long SIZEOF_LONG)
	MESSAGE(STATUS "sizeof(long) = ${SIZEOF_LONG}")
	if (SIZEOF_LONG EQUAL 8)
		set (LD_LIBDIR "lib64")
	else ()
		set (LD_LIBDIR "lib")
	endif ()
	MESSAGE("LD_LIBDIR set to ${LD_LIBDIR} (default)")
endif()

if (PKGCONFIG_DIRECTORY)
	MESSAGE("PKGCONFIG_DIRECTORY explicitely set to ${PKGCONFIG_DIRECTORY}")
else ()
	set(PKGCONFIG_DIRECTORY "${CMAKE_INSTALL_PREFIX}/${LD_LIBDIR}/pkgconfig")
	MESSAGE("PKGCONFIG_DIRECTORY set to ${PKGCONFIG_DIRECTORY} (default)")
endif ()

set (GRIDD_PLUGINS_DIRECTORY "${LD_LIBDIR}/grid")
if (DEFINED GRIDD_PLUGINS)
	set(GRIDD_PLUGINS_DIRECTORY "${GRIDD_PLUGINS}")
endif ()

###-------------------------------------------------------------------------###

# Set defaults
set(DEFAULT_LIBRARY_DIRS "/usr/${LD_LIBDIR}")
set(DEFAULT_INCLUDE_DIRS "/usr/include")
set(APACHE2_LIBRARY_DIRS "${DEFAULT_LIBRARY_DIRS}/httpd")
set(APACHE2_INCLUDE_DIRS "${DEFAULT_INCLUDE_DIRS}/httpd")
set(ATTR_INCLUDE_DIRS "${DEFAULT_INCLUDE_DIRS}/attr")
set(ZK_INCLUDE_DIRS "${DEFAULT_INCLUDE_DIRS}/zookeeper")

# check system configuration
pkg_search_module(JSONC json json-c)
pkg_check_modules(GLIB2 REQUIRED glib-2.0 gthread-2.0 gmodule-2.0)
#pkg_check_modules(CURL curl libcurl)
pkg_check_modules(LIBEC erasurecode)

if (NOT SDK_ONLY)
pkg_check_modules(APR REQUIRED apr-1)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(ZMQ libzmq>=4.0.0)
# Optional cache libraries
pkg_search_module(HIREDIS hiredis)
pkg_search_module(LIBMEMCACHED libmemcached)

endif (NOT SDK_ONLY)

# Load CLI-overriden configuration
option_or_system(CURL curl curl/curl.h)
option_or_system(JSONC json-c json.h)
option_or_system(LIBEC erasurecode erasurecode.h)

if (NOT SDK_ONLY)
option_or_system(APACHE2 modules/mod_webdav.so httpd.h)
option_or_system(ATTR attr attr/libattr.h)
option_or_system(ZK zookeeper_mt zookeeper.h)
option_or_system(ZLIB z zlib.h)
option_or_system(ZMQ zmq zmq.h zmq_utils.h)
option_or_system(LEVELDB leveldb leveldb/c.h)

if (ASN1C_EXE)
	set(ASN1C_EXECUTABLE ${ASN1C_EXE})
else()
	find_program(ASN1C_EXECUTABLE asn1c)
endif()
set(ASN1C_EXE_OPTS "-fwide-types")

find_program(GO_EXECUTABLE go)
endif (NOT SDK_ONLY)

if (NOT SDK_ONLY)
test_CLI(GO_EXECUTABLE "go")
test_CLI(FLEX_EXECUTABLE "flex")
test_CLI(BISON_EXECUTABLE "bison")
test_CLI(ASN1C_EXECUTABLE "asn1c")
endif(NOT SDK_ONLY)

# Check every required module is present
if (NOT DEFINED ALLOW_HIREDIS)
	MESSAGE("hiredis disabled by default, activate with -DALLOW_HIREDIS=1")
endif ()
print_found("HIREDIS")

if (NOT DEFINED ALLOW_LIBMEMCACHED)
	MESSAGE("libmemcached disabled by default, activate with -DALLOW_LIBMEMCACHED=1")
endif ()
print_found("LIBMEMCACHED")

check_found("CURL" "GLIB2" "JSONC" "LIBEC")

if (NOT SDK_ONLY)
check_found("APR" "APACHE2" "ATTR" "SQLITE3" "ZMQ" "ZK" "PYTHONINTERP" "LEVELDB" "ZLIB")

if (DEFINED APACHE2_MODDIR)
	set (APACHE2_MODULES_DIRS ${APACHE2_MODDIR})
else ()
	set (APACHE2_MODULES_DIRS ${APACHE2_LIBRARY_DIRS}/modules)
endif ()
endif (NOT SDK_ONLY)

ENABLE_TESTING()

set(CMAKE_LIBRARY_PATH "")
set(CMAKE_INCLUDE_PATH "")
include_directories(AFTER
		${GLIB2_INCLUDE_DIRS})

link_directories(${GLIB2_LIBRARY_DIRS})

add_subdirectory(./core)

if (NOT SDK_ONLY)
add_subdirectory(./metautils/lib)
add_subdirectory(./cache)
add_subdirectory(./cluster/lib)

add_subdirectory(./cluster/module)
add_subdirectory(./cluster/tools)
add_subdirectory(./meta0v2)
add_subdirectory(./meta1v2)
add_subdirectory(./meta2v2)
add_subdirectory(./proxy)
add_subdirectory(./events)
add_subdirectory(./rawx)
add_subdirectory(./rawx-apache2/src)
add_subdirectory(./rawx-lib/src)
add_subdirectory(./rawx-lib/tools)
add_subdirectory(./resolver)
add_subdirectory(./server)
add_subdirectory(./sqliterepo)
add_subdirectory(./sqlx)
add_subdirectory(./rdir)
add_subdirectory(./tools)
add_subdirectory(./tests/unit)
add_subdirectory(./tests/func)
add_subdirectory(./tools/event-benchmark)
endif (NOT SDK_ONLY)

add_custom_target(python-openio-docs
	COMMAND epydoc -v --graph=all --docformat=restructuredtext -o python-openio-docs oio)
