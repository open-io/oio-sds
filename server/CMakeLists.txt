add_definitions(-DG_LOG_DOMAIN="oio.srv")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR})

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/server_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/server_variables.h
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
		"server"
		${CMAKE_SOURCE_DIR}/conf.json)


add_library(statsd-client STATIC
		${CMAKE_SOURCE_DIR}/vendor/statsd-c-client/statsd-client.c
)
# Disable this warning only for this lib (not maintained by us)
target_compile_options(statsd-client PRIVATE -Wno-float-equal)

add_library(server STATIC
		slab.c
		network_server.c
		transport_gridd.c
		${CMAKE_CURRENT_BINARY_DIR}/server_variables.c)

target_link_libraries(server
		statsd-client
		metautils
		-lm ${GLIB2_LIBRARIES})

