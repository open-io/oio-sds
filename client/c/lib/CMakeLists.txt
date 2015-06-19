include_directories(BEFORE .
		 ../../..
		${CMAKE_CURRENT_BINARY_DIR}/../../..)

include_directories(AFTER
		${NEON_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS})

link_directories(
		${NEON_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS})

add_library(gridclient SHARED
		containers.c
		content_download.c
		content_shortcuts.c
		content_upload.c
		contents.c
		grid.c
		gs_common.c
		rawx.c
		rainx.c
		rainx_remote.c
		meta_resolver_explicit.c
		hc_directory.c
		loc_context.c
		hc_func.c
		hcadmin_func.c
		http_put.c
)

set_target_properties(gridclient PROPERTIES
		PUBLIC_HEADER "grid_client.h"
		SOVERSION ${ABI_VERSION})

target_link_libraries(gridclient
		metautils
		gridcluster
		meta2v2utils
		meta2v2remote
		meta0remote
		meta1remote
		meta0utils
		hcresolve
		sqlitereporemote
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES} ${CURL_LIBRARIES})


add_executable(test_include test_include.c)
target_link_libraries(test_include gridclient)

add_executable(test_url test_url.c)
target_link_libraries(test_url gridclient)

add_executable(test_references test_references.c)
target_link_libraries(test_references gridclient)

add_executable(test_services test_services.c)
target_link_libraries(test_services gridclient)

if (MHD_FOUND)
	include_directories(AFTER ${MHD_INCLUDE_DIRS})
	link_directories(${MHD_LIBRARY_DIRS})
	add_executable(test_http_put test_http_put.c)
	target_link_libraries(test_http_put gridclient microhttpd)
	add_test(NAME client/lib/http_put COMMAND test_http_put)
endif(MHD_FOUND)

install(FILES
			grid_client_shortcuts.h
			hc.h
        DESTINATION include
        PERMISSIONS
            OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS
			gridclient
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

add_test(NAME client/lib/inc COMMAND test_include)
add_test(NAME client/lib/url COMMAND test_url)
add_test(NAME client/metacd/get_container COMMAND test_metacd)
add_test(NAME client/lib/ref COMMAND test_references)
add_test(NAME client/lib/ser COMMAND test_services)
