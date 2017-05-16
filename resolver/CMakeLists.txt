add_definitions(-DG_LOG_DOMAIN="oio.resolver")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR})

include_directories(AFTER
		${CMAKE_BINARY_DIR}
		${CMAKE_BINARY_DIR}/metautils/lib)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/resolver_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/resolver_variables.h
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
		"resolver"
		${CMAKE_SOURCE_DIR}/conf.json)


add_library(hcresolve SHARED
	hc_resolver.c
	${CMAKE_CURRENT_BINARY_DIR}/resolver_variables.c
	${CMAKE_CURRENT_BINARY_DIR}/resolver_variables.h)

target_link_libraries(hcresolve
		meta0remote meta1remote metautils gridcluster
		${GLIB2_LIBRARIES})

install(TARGETS hcresolve
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

