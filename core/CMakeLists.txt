add_definitions(-DG_LOG_DOMAIN="oio.core")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

if (GLIB2_glib-2.0_VERSION VERSION_GREATER_EQUAL 2.68.0)
    add_definitions(-DHAS_GLIB_MEMDUP2=1)
endif()

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
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

add_library(oiocore SHARED
	url2.c
	url.c
	cfg.c
	str.c
	errors.c
	ext.c
	log.c
	loc.c
	var.c
	lb.c
	lrutree.c
	${CMAKE_CURRENT_BINARY_DIR}/client_variables.c
	${CMAKE_CURRENT_BINARY_DIR}/lb_variables.c)

set_target_properties(oiocore PROPERTIES PUBLIC_HEADER "oio_core.h" VERSION 0.0.0 SOVERSION 0)
target_link_libraries(oiocore
		${JSONC_LIBRARIES} ${GLIB2_LIBRARIES})

add_library(oiosds SHARED
	http_put.c
	http_del.c
	headers.c
	proxy.c
	sds.c
	dir.c
	cs.c)

set_target_properties(oiosds PROPERTIES PUBLIC_HEADER "oio_sds.h" VERSION 0.0.0 SOVERSION 0)
target_link_libraries(oiosds oiocore
		${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES})

add_executable(tool_sdk_noconf tool_sdk_noconf.c)
target_link_libraries(tool_sdk_noconf oiosds)

add_executable(tool_sdk tool_sdk.c)
target_link_libraries(tool_sdk oiosds)

add_executable(tool_roundtrip tool_roundtrip.c)
target_link_libraries(tool_roundtrip oiosds)

install(TARGETS
			oiocore
			oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

install(TARGETS
			tool_sdk_noconf
			tool_roundtrip
			tool_sdk
		DESTINATION bin
		CONFIGURATIONS Debug)
