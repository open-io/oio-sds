add_definitions(-DG_LOG_DOMAIN="oio.m0v2" -DTHREADED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_SOURCE_DIR}
		${CMAKE_BINARY_DIR}
		${CMAKE_BINARY_DIR}/metautils/lib
		${CMAKE_BINARY_DIR}/metautils/asn1c
		${CMAKE_CURRENT_BINARY_DIR})

include_directories(AFTER
		${ZK_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

add_library(meta0remote STATIC meta0_remote.c)
target_link_libraries(meta0remote
		metautils
		${GLIB2_LIBRARIES})


add_library(meta0utils STATIC meta0_utils.c)
target_link_libraries(meta0utils
		metautils
		${GLIB2_LIBRARIES})


add_library(meta0v2 STATIC meta0_backend.c)
target_link_libraries(meta0v2
		meta0utils metautils sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


add_executable(meta0_client meta0_client.c)
bin_prefix(meta0_client -meta0-client)
target_link_libraries(meta0_client
		gridcluster
		meta0remote meta0utils metautils)


add_executable(meta0_server
		zk_manager.c
		meta0_gridd_dispatcher.c
		meta0_server.c)
bin_prefix(meta0_server -meta0-server)
target_link_libraries(meta0_server
		meta0v2 meta0utils
		metautils server sqliterepo
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(TARGETS meta0_server meta0_client RUNTIME DESTINATION bin)

# As soon as the admin CLI is able to efficiently check a meta0
# service without that command, we can uncomment the directive that
# reserve the tool for the DEVEL use cases.
install(TARGETS
			meta0_client
		RUNTIME DESTINATION bin
		#CONFIGURATIONS Debug
		COMPONENT dev)
