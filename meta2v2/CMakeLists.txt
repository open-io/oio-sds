set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${NEON_INCLUDE_DIRS}
		${LIBRAIN_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS}
		${LIBRAIN_LIBRARY_DIRS})

add_custom_command(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/autogen.c ${CMAKE_CURRENT_BINARY_DIR}/autogen.h
	COMMAND ${PYTHON_EXECUTABLE}
	ARGS ${CMAKE_CURRENT_SOURCE_DIR}/m2gen.py ${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS m2gen.py
)

add_library(meta2v2lbutils SHARED
		meta2_utils_lb.h
		meta2_utils_lb.c
)

target_link_libraries(meta2v2lbutils
		metautils gridcluster
		${GLIB2_LIBRARIES}
)

add_library(meta2v2utils SHARED
		generic.c
		generic.h
		${CMAKE_CURRENT_BINARY_DIR}/autogen.c
		${CMAKE_CURRENT_BINARY_DIR}/autogen.h
		meta2_utils.c
		meta2_type_converter.c
		meta2_utils_snapshots.c
		meta2_utils_check.c
		meta2_utils.h
		meta2_bean.c
		meta2_bean_utils.c
		meta2_bean.h
		meta2_macros.h
		meta2_backend_dbconvert.h
		meta2_backend_dbconvert.c
		meta2_dedup_utils.h
		meta2_dedup_utils.c
)

target_link_libraries(meta2v2utils
		metautils gridcluster sqliteutils rain
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(meta2v2remote SHARED
		meta2v2_remote.h
		meta2v2_remote.c
		meta2_macros.h)

target_link_libraries(meta2v2remote
		meta2v2utils metacomm metautils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(meta2v2 SHARED
		${CMAKE_CURRENT_BINARY_DIR}/autogen.h generic.h
		meta2_utils.h
		meta2_macros.h
		meta2_backend.h
		meta2_backend.c)

target_link_libraries(meta2v2
		metautils sqliterepo
		meta2remote meta1remote
		meta0remote meta0utils
		meta2v2utils meta2v2lbutils meta2v2remote
		sqlxsrv
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(meta2_server
		meta2_gridd_dispatcher.c
		meta2_filters_extract.c
		meta2_filters_check.c
		meta2_filters_misc.c
		meta2_filters_action_url.c
		meta2_filters_action_container.c
		meta2_filters_action_content.c
		meta2_filters_action_events.c
		meta2_filter_context.c
		meta2_server.c)
bin_prefix_full(meta2_server -meta2-server)

target_link_libraries(meta2_server meta2v2
        hcresolve metacomm metautils gridcluster server
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(test_meta2_backend test_meta2_backend.c)
target_link_libraries(test_meta2_backend
		meta2v2 ${GLIB2_LIBRARIES})

add_executable(test_meta2_client test_meta2_client.c)
target_link_libraries(test_meta2_client
		meta2remote meta2servicesremote
		meta2v2 metautils ${GLIB2_LIBRARIES})

add_executable(test_meta2_type_converter test_meta2_type_converter.c)
target_link_libraries(test_meta2_type_converter
		meta2v2 metautils ${GLIB2_LIBRARIES})

add_executable(test_meta2_dedup test_meta2_dedup.c meta2_test_common.c)
target_link_libraries(test_meta2_dedup
		meta2v2 meta2v2utils metautils meta2v2remote
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(test_meta2_check test_meta2_check.c)
target_link_libraries(test_meta2_check
		meta2v2utils metautils meta2v2remote
		gridcluster 
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(FILES
			${CMAKE_CURRENT_BINARY_DIR}/autogen.h
			generic.h
			meta2_backend_dbconvert.h
			meta2_backend.h
			meta2_backend_internals.h
			meta2_bean.h
			meta2_events.h
			meta2_dedup_utils.h
			meta2_filter_context.h
			meta2_filters.h
			meta2_gridd_dispatcher.h
			meta2_macros.h
			meta2_test_common.h
			meta2_utils.h
			meta2_utils_lb.h
			meta2v2_remote.h
		DESTINATION include/meta2v2
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)


install(TARGETS meta2v2 meta2v2remote meta2_server meta2v2utils meta2v2lbutils
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

add_test(NAME meta2/backend COMMAND test_meta2_backend)
add_test(NAME meta2/converter COMMAND test_meta2_type_converter)

