set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

include_directories(BEFORE . ..)

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

add_library(meta1v2 SHARED
		compound_types.c compound_types.h
		meta1_backend_internals.h
		meta1_backend.h
		meta1_backend.c
		meta1_backend_internals.c
		meta1_backend_services.c
		meta1_backend_properties.c
		meta1_backend_references.c
		meta1_prefixes.c meta1_prefixes.h
		internals.h internals_sqlite.h)

set_target_properties(meta1v2 PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta1v2
		meta0utils metacomm metautils meta2remote gridcluster meta0remote sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(meta1remote SHARED common.c meta1_remote.c meta1_remote.h)
set_target_properties(meta1remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta1remote
		metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(meta1_backend_test meta1_backend_test.c)
target_link_libraries(meta1_backend_test
		meta1v2 meta0utils metautils server sqliterepo)

add_executable(meta1_server meta1_gridd_dispatcher.c meta1_server.c)
bin_prefix_full(meta1_server -meta1-server)
target_link_libraries(meta1_server meta1v2
        meta0utils metacomm metautils gridcluster server sqliterepo
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(test_m1v2_list_refs test_m1v2_list_refs.c)
target_link_libraries(test_m1v2_list_refs
		meta1remote ${GLIB2_LIBRARIES})

add_executable(meta1_client meta1_client.c)
bin_prefix_full(meta1_client -meta1-client)
target_link_libraries(meta1_client metautils metacomm meta1remote)

install(FILES
			meta1_backend.h
			meta1_gridd_dispatcher.h
			meta1_prefixes.h
			meta1_remote.h
        DESTINATION include/meta1v2
        PERMISSIONS
            OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS meta1v2 meta1_server meta1remote meta1_client
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

