include_directories(BEFORE . .. ../..
		../../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/../..
)

include_directories(AFTER
		${DB_INCLUDE_DIRS}
		${PYTHON_INCLUDE_PATH}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_library(integrity SHARED
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

target_link_libraries(integrity
		metautils metacomm gridclient gridcluster
		meta0remote meta1remote meta2remote rawxclient
		hcresolve meta2v2lbutils
		-ldb ${SQLITE3_LIBRARIES} ${CURL_LIBRARIES} ${LIBEVENT_LIBRARIES})

install(TARGETS integrity
		LIBRARY DESTINATION ${LD_LIBDIR})

