add_definitions(-DG_LOG_DOMAIN="oio.core")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${LIBEC_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${LIBEC_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/client_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/client_variables.h
	DEPENDS
		${CMAKE_SOURCE_DIR}/confgen.py
		${CMAKE_SOURCE_DIR}/conf.json
	PRE_BUILD
	COMMENT
		"Generating the central configuration"
	COMMAND
		${PYTHON_EXECUTABLE}
	ARGS
		${CMAKE_SOURCE_DIR}/confgen.py
		"client"
		${CMAKE_SOURCE_DIR}/conf.json)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/lb_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/lb_variables.h
	DEPENDS
		${CMAKE_SOURCE_DIR}/confgen.py
		${CMAKE_SOURCE_DIR}/conf.json
	PRE_BUILD
	COMMENT
		"Generating the central load-balancer configuration"
	COMMAND
		${PYTHON_EXECUTABLE}
	ARGS
		${CMAKE_SOURCE_DIR}/confgen.py
		"lb"
		${CMAKE_SOURCE_DIR}/conf.json)

add_library(oiocore SHARED url.c cfg.c str.c ext.c log.c lb.c var.c
	${CMAKE_CURRENT_BINARY_DIR}/client_variables.h
	${CMAKE_CURRENT_BINARY_DIR}/client_variables.c
	${CMAKE_CURRENT_BINARY_DIR}/lb_variables.h
	${CMAKE_CURRENT_BINARY_DIR}/lb_variables.c)

target_link_libraries(oiocore
		${JSONC_LIBRARIES} ${GLIB2_LIBRARIES} ${LIBEC_LIBRARIES})
set_target_properties(oiocore PROPERTIES
		PUBLIC_HEADER "oio_core.h"
		SOVERSION ${ABI_VERSION})

add_library(oiosds SHARED
	http_put.c
	http_del.c
	http_get.c
	headers.c
	proxy.c
	sds.c dir.c cs.c)
target_link_libraries(oiosds oiocore
		${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES} ${LIBEC_LIBRARIES})
set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

add_executable(tool_sdk_noconf tool_sdk_noconf.c)
target_link_libraries(tool_sdk_noconf oiosds)

add_executable(tool_sdk tool_sdk.c)
target_link_libraries(tool_sdk oiosds)

add_executable(tool_roundtrip tool_roundtrip.c)
target_link_libraries(tool_roundtrip oiosds)

install(FILES
		oiocfg.h
		oiodir.h
		oioext.h
		oiolog.h
		oiostr.h
		oiourl.h
		oiovar.h
		oiocs.h
		oiolb.h
		DESTINATION include/core)

install(TARGETS oiocore oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

