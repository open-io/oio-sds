add_definitions(-DG_LOG_DOMAIN="oio.m2v2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_BINARY_DIR}
		${CMAKE_BINARY_DIR}/metautils/lib
		${CMAKE_BINARY_DIR}/metautils/asn1c)

include_directories(AFTER
		${JSONC_INCLUDE_DIRS}
		${LIBRAIN_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${JSONC_LIBRARY_DIRS}
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS}
		${LIBRAIN_LIBRARY_DIRS})

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/meta2_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/meta2_variables.h
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
		"meta2"
		${CMAKE_SOURCE_DIR}/conf.json)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/autogen_storage.c
		${CMAKE_CURRENT_BINARY_DIR}/autogen_codec.c
		${CMAKE_CURRENT_BINARY_DIR}/autogen.h
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/m2gen.py
	COMMAND
		${PYTHON_EXECUTABLE}
	ARGS
		${CMAKE_CURRENT_SOURCE_DIR}/m2gen.py
		${CMAKE_CURRENT_BINARY_DIR}
)

add_library(meta2v2utils STATIC
		${CMAKE_CURRENT_BINARY_DIR}/autogen_codec.c
		${CMAKE_CURRENT_BINARY_DIR}/meta2_variables.c
		meta2_utils_lb.c
		generic.c
		meta2_bean.c
		meta2_bean_utils.c
		meta2_utils_json_in.c
		meta2_utils_json_out.c)

target_link_libraries(meta2v2utils
		metautils
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES})


add_library(meta2v2 STATIC
		${CMAKE_CURRENT_BINARY_DIR}/autogen_storage.c
		generic_backend.c
		meta2_utils.c
		meta2_backend.c)

target_link_libraries(meta2v2
		metautils sqliterepo
		meta1remote meta0remote meta0utils
		meta2v2utils
		oioevents
		${GLIB2_LIBRARIES} ${RABBITMQ_LIBRARIES} ${SQLITE3_LIBRARIES})


add_executable(meta2_server
		meta2_gridd_dispatcher.c
		meta2_filters_extract.c
		meta2_filters_check.c
		meta2_filters_misc.c
		meta2_filters_action_container.c
		meta2_filters_action_content.c
		meta2_filter_context.c
		meta2_server.c)
bin_prefix(meta2_server -meta2-server)

target_link_libraries(meta2_server
		meta2v2
		hcresolve metautils server
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(TARGETS meta2_server RUNTIME DESTINATION bin)
