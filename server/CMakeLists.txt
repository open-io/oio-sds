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


add_library(server SHARED
		slab.c
		network_server.c
        transport_gridd.c
		${CMAKE_CURRENT_BINARY_DIR}/server_variables.c)

set_target_properties(server PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(server
		metautils
		-lm ${GLIB2_LIBRARIES})

install(TARGETS server
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

