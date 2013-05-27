include_directories(BEFORE .
		../../metautils/lib
		../../meta0/remote
		../../meta1/remote
		../../meta2/remote
		../../client/c/lib
		../../rawx-client/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events
		../../rawx-lib/src
		../../rules-motor/lib)

include_directories(AFTER
		${DB_INCLUDE_DIRS}
		${PYTHON_INCLUDE_PATH}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_library(integrity SHARED
	chunk_db.c alert.c chunk_check.c meta2_check.c
	broken_event.c service_cache.c volume_scanner.c
	content_check.c content_check_tools.c)

set_target_properties(integrity PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(integrity
		metautils metacomm gridclient
		meta0remote meta1remote meta2remote rawx rawxclient
		-ldb ${SQLITE3_LIBRARIES} ${LIBEVENT_LIBRARIES})

install(TARGETS integrity
		LIBRARY DESTINATION ${LD_LIBDIR})

