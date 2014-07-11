#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

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
		metautils metacomm gridcluster
		${GLIB2_LIBRARIES})


add_library(meta0v2 SHARED meta0_backend.h meta0_backend.c
meta0_prefixassign.h meta0_prefixassign.c)
set_target_properties(meta0v2 PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta0v2
		meta0utils metacomm metautils gridcluster sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


add_executable(meta0_client meta0_client.c)
bin_prefix_full(meta0_client -meta0-client)
target_link_libraries(meta0_client gridcluster
		meta0remote meta0utils metautils server)


add_executable(meta0_init meta0_init.c)
bin_prefix_full(meta0_init -meta0-init)
target_link_libraries(meta0_init gridcluster
		meta0remote meta0utils metautils server)


#add_executable(meta0_backend_test meta0_backend_test.c)
#target_link_libraries(meta0_backend_test
#		meta0v2 metautils server sqliterepo)


add_executable(meta0_server
		meta0_gridd_dispatcher.c meta0_server.c)
bin_prefix_full(meta0_server -meta0-server)
target_link_libraries(meta0_server
		meta0v2 meta0utils
        metacomm metautils gridcluster server sqliterepo
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(FILES
			meta0_backend.h
			meta0_gridd_dispatcher.h
			meta0_prefixassign.h
			meta0_remote.h
			meta0_utils.h
        DESTINATION include/meta0v2
        PERMISSIONS
            OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)


install(TARGETS meta0utils meta0remote meta0v2 meta0_server meta0_client meta0_init
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

install(TARGETS meta0remote
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

