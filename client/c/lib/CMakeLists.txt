include_directories(BEFORE .
		 ../../..
		${CMAKE_CURRENT_BINARY_DIR}/../../..
		../../../metautils/lib)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${NEON_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS})

link_directories(
		${SQLITE3_LIBRARY_DIRS})

add_library(gridclient SHARED
		containers.c
		content_download.c
		content_shortcuts.c
		content_upload.c
		contents.c
		snapshots.c
		grid.c
		grid_client.h
		grid_client_shortcuts.h
		grid_index.c
		grid_services.c
		gs_common.c
		gs_internals.h
		rawx.c rawx.h
		rainx.c rainx.h
		rainx_remote.c rainx_remote.h
		meta_resolver_explicit.c meta_resolver_explicit.h
		meta_resolver_metacd.c meta_resolver_metacd.h
		metacd_remote.c metacd_remote.h
		round_buffer.c round_buffer.h
		round_buffer_test.c
		hc_directory.c
		loc_context.c loc_context.h
		hc_func.c hc_help.c hc.h
		hcadmin_func.c hcadmin.h
)

set_target_properties(gridclient PROPERTIES
		PUBLIC_HEADER "grid_client.h"
		SOVERSION ${ABI_VERSION})

target_link_libraries(gridclient
		metautils metacomm
		gridcluster
		meta2remote
		meta2servicesremote
		meta2v2utils
		meta2v2remote
		meta0remote
		meta1remote
		meta0utils
		hcresolve
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES} ${CURL_LIBRARIES})


add_library(solrutils SHARED solr_utils.c)
target_link_libraries(solrutils
		metautils metacomm gridclient
		${GLIB2_LIBRARIES})

#set_target_properties(solrutils PROPERTIES
#		PUBLIC_HEADER "solr_utils.h"
#		SOVERSION ${ABI_VERSION})

add_executable(test_include test_include.c)
target_link_libraries(test_include gridclient)

add_executable(test_url test_url.c)
target_link_libraries(test_url gridclient)

add_executable(test_metacd test_metacd.c)
target_link_libraries(test_metacd gridclient)

install(FILES
			grid_client_shortcuts.h
#        DESTINATION include/client/c/lib
        DESTINATION include
        PERMISSIONS
            OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS
			gridclient solrutils
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

add_test(NAME client/lib/inc COMMAND test_include)
add_test(NAME client/lib/url COMMAND test_url)
add_test(NAME client/metacd/get_container COMMAND test_metacd)
