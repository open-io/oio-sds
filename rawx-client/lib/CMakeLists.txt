include_directories(BEFORE . ../..)

add_library(rawxclient SHARED
		session.c parser.c stats.c directory_data.c)

set_target_properties(rawxclient PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rawxclient
		metautils
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

install(FILES
			rawx_client.h
        DESTINATION include/rawx-client/lib
        PERMISSIONS
            OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS rawxclient LIBRARY DESTINATION ${LD_LIBDIR})
