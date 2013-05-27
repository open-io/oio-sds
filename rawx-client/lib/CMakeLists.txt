include_directories(BEFORE .
	../../metautils/lib
	../../rawx-lib/src)

add_library(rawxclient SHARED session.c parser.c stats.c directory_data.c)

set_target_properties(rawxclient PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rawxclient
		metautils
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS rawxclient LIBRARY DESTINATION ${LD_LIBDIR})
