add_definitions(-DG_LOG_DOMAIN="oio.fabx")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
		${CMAKE_SOURCE_DIR}
		${CMAKE_BINARY_DIR})

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${FABRIC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${FABRIC_LIBRARY_DIRS})

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/fabx_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/fabx_variables.h
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
		"fabx"
		${CMAKE_SOURCE_DIR}/conf.json)

add_executable(fabx
	server.c
	common.c
	${CMAKE_CURRENT_BINARY_DIR}/fabx_variables.c)

bin_prefix(fabx -fabx)

target_link_libraries(fabx
		metautils
		${GLIB2_LIBRARIES}
		${FABRIC_LIBRARIES})

install(TARGETS fabx
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)


