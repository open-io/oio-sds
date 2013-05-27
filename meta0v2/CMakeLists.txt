
include_directories(BEFORE .
		../metautils/lib
		../sqliterepo
		../cluster/agent ../cluster/events ../cluster/lib
		../server
		../meta0/remote)

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(meta0remote SHARED meta0_remote.c meta0_remote.h)
set_target_properties(meta0remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0remote
		metautils metacomm
		${GLIB2_LIBRARIES})


add_library(meta0utils SHARED meta0_utils.c meta0_utils.h)
set_target_properties(meta0utils PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0utils
		metautils metacomm
		${GLIB2_LIBRARIES})


add_library(meta0v2 SHARED meta0_backend.h meta0_backend.c
meta0_prefixassign.h meta0_prefixassign.c)
set_target_properties(meta0v2 PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0v2
		meta0utils metacomm metautils gridcluster sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


add_executable(meta0_client meta0_client.c)
target_link_libraries(meta0_client gridcluster
		meta0remote meta0utils metautils server)


add_executable(meta0_init meta0_init.c)
target_link_libraries(meta0_init gridcluster
		meta0remote meta0utils metautils server)


#add_executable(meta0_backend_test meta0_backend_test.c)
#target_link_libraries(meta0_backend_test
#		meta0v2 metautils server sqliterepo)


add_executable(meta0_server
		meta0_gridd_dispatcher.c meta0_server.c)
target_link_libraries(meta0_server
		meta0v2 meta0utils
        metacomm metautils gridcluster server sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


install(TARGETS meta0utils meta0remote meta0v2 meta0_server meta0_client meta0_init
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

install(TARGETS meta0remote
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

