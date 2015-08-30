add_definitions(-DG_LOG_DOMAIN="oio.m0v2")

include_directories(BEFORE . ..)

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(meta0remote SHARED meta0_remote.c meta0_remote.h)
set_target_properties(meta0remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0remote
		metautils
		${GLIB2_LIBRARIES})


add_library(meta0utils SHARED meta0_utils.c meta0_utils.h)
set_target_properties(meta0utils PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0utils
		metautils gridcluster-remote
		${GLIB2_LIBRARIES})


add_library(meta0v2 SHARED meta0_backend.h meta0_backend.c
meta0_prefixassign.h meta0_prefixassign.c)
set_target_properties(meta0v2 PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0v2
		meta0utils metautils gridcluster-remote sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


add_executable(meta0_client meta0_client.c)
bin_prefix(meta0_client -meta0-client)
target_link_libraries(meta0_client
		gridcluster-remote
		meta0remote meta0utils metautils server)


add_executable(meta0_init meta0_init.c)
bin_prefix(meta0_init -meta0-init)
target_link_libraries(meta0_init
		gridcluster-remote
		meta0remote meta0utils metautils server)


add_executable(meta0_server
		meta0_gridd_dispatcher.c meta0_server.c)
bin_prefix(meta0_server -meta0-server)
target_link_libraries(meta0_server
		meta0v2 meta0utils
        metautils gridcluster-remote server sqliterepo
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(TARGETS
			meta0utils
			meta0remote
			meta0v2
			meta0_server
			meta0_client
			meta0_init
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

