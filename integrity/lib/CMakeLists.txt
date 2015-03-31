include_directories(BEFORE . ../..
		../../client/c/lib
		../../rawx-lib/src
		${CMAKE_CURRENT_BINARY_DIR}/../..
)

include_directories(AFTER
		${DB_INCLUDE_DIRS}
		${PYTHON_INCLUDE_PATH}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS}
		${LIBRAIN_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${LIBRAIN_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_library(integrity SHARED
	meta2_utils_check.c meta2_utils_check.h
	check.c check.h
	chunk_db.c chunk_db.h
	alert.c alert.h
	chunk_check.c
	meta2_check.c meta2_check.h
	broken_event.c broken_event.h
	service_cache.c service_cache.h
	content_check.c content_check.h
	content_check_tools.c
	policycheck_repair.c policycheck_repair.h
	http_pipe.c http_pipe.h)

set_target_properties(integrity
	PROPERTIES SOVERSION ${ABI_VERSION})

add_executable(test_meta2_check test_meta2_check.c)
target_link_libraries(test_meta2_check
		meta2v2utils metautils meta2v2remote
		gridcluster integrity
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

target_link_libraries(integrity
		metautils gridclient gridcluster
		meta0remote meta1remote meta2remote rawxclient rawx
		hcresolve meta2v2lbutils
		${DB_LIBRARIES} ${SQLITE3_LIBRARIES} ${CURL_LIBRARIES} ${LIBEVENT_LIBRARIES})

install(TARGETS integrity
		LIBRARY DESTINATION ${LD_LIBDIR})

add_test(NAME integrity/check COMMAND test_meta2_check)

