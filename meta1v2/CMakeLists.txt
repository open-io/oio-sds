add_definitions(-DG_LOG_DOMAIN="oio.m1v2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_SOURCE_DIR}
		${CMAKE_BINARY_DIR}
		${CMAKE_CURRENT_BINARY_DIR}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${JSONC_LIBRARY_DIRS}
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

add_library(meta1v2 STATIC
		meta1_backend.c
		meta1_backend_internals.c
		meta1_backend_services.c
		meta1_backend_properties.c
		meta1_backend_references.c
		meta1_prefixes.c)

target_link_libraries(meta1v2
		metautils gridcluster sqliterepo
		meta0utils meta0remote
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(meta1remote STATIC meta1_remote.c)
target_link_libraries(meta1remote
		metautils
		${GLIB2_LIBRARIES})

add_executable(meta1_server meta1_gridd_dispatcher.c meta1_server.c)
bin_prefix(meta1_server -meta1-server)
target_link_libraries(meta1_server meta1v2
		meta0utils metautils server sqliterepo
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(TARGETS meta1_server RUNTIME DESTINATION bin)
