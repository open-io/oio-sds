include_directories(BEFORE .
		../metautils/lib
		../sqliterepo
		../server
		../meta0v2
		../meta1v2
		../meta2/remote
		../cluster/agent
		../cluster/events
		../cluster/lib
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib
)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${NEON_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/../meta2/remote)

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

add_custom_command(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/autogen.c ${CMAKE_CURRENT_BINARY_DIR}/autogen.h
	COMMAND ${PYTHON_EXECUTABLE}
	ARGS ${CMAKE_CURRENT_SOURCE_DIR}/m2gen.py ${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS m2gen.py
)

add_library(meta2v2utils SHARED
		generic.c
		generic.h
		${CMAKE_CURRENT_BINARY_DIR}/autogen.c
		${CMAKE_CURRENT_BINARY_DIR}/autogen.h
		meta2_utils.c
		meta2_type_converter.c
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
		metautils gridcluster sqliteutils
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
		meta2v2utils metautils sqliterepo meta2remote
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

install(TARGETS meta2v2 meta2v2remote meta2_server meta2v2utils
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

add_test(NAME meta2/backend COMMAND test_meta2_backend)
add_test(NAME meta2/converter COMMAND test_meta2_type_converter)

