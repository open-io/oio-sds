add_definitions(-DG_LOG_DOMAIN="oio.proxy")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

add_definitions(-DHAVE_UGLY_RC_FUNCTIONS=1)

include_directories(BEFORE
		${CMAKE_SOURCE_DIR}
		${CMAKE_CURRENT_BINARY_DIR}/..
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
		${CMAKE_CURRENT_BINARY_DIR}/proxy_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/proxy_variables.h
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
		"proxy"
		${CMAKE_SOURCE_DIR}/conf.json)

add_executable(metacd_http
	meta2v2_remote.c
    metacd_http.c
    common.c
    admin_actions.c
    cache_actions.c
    cs_actions.c
    lb_actions.c
    dir_actions.c
    m2_actions.c
    sqlx_actions.c
    reply.c
    path_parser.c
    transport_http.c
	${CMAKE_CURRENT_BINARY_DIR}/proxy_variables.c)

bin_prefix(metacd_http -proxy)

target_link_libraries(metacd_http
		metautils server hcresolve gridcluster
		meta2v2utils
		meta1remote sqlitereporemote
		meta0remote meta0utils
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES} ${CURL_LIBRARIES})

install(TARGETS metacd_http
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

