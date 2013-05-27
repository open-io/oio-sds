include_directories(BEFORE .
		../../../metautils/lib
		../../../libdbaccess/lib
		../../../cluster/lib ../../../cluster/agent ../../../cluster/events
		../../../meta2v2
		../../../meta1v2
		../../../meta0v2
		../../../meta2/remote
		${CMAKE_CURRENT_BINARY_DIR}/../../../meta2v2
		${CMAKE_CURRENT_BINARY_DIR}/../../../meta2/remote)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${NEON_INCLUDE_DIRS})

link_directories(
		${SQLITE3_LIBRARY_DIRS})

add_library(gridclient SHARED
		containers.c
		content_download.c
		content_shortcuts.c
		content_upload.c
		contents.c
		grid.c
		grid_client.h
		grid_client_shortcuts.h
		grid_index.c
		grid_services.c
		gs_common.c
		gs_internals.h
		rawx.c rawx.h
		meta_resolver_explicit.c meta_resolver_explicit.h
		meta_resolver_metacd.c meta_resolver_metacd.h
		metacd_remote.c metacd_remote.h
		round_buffer.c round_buffer.h
		round_buffer_test.c
		hc_directory.c
		loc_context.c loc_context.h
		hc_func.c hc_help.c hc.h
)

set_target_properties(gridclient PROPERTIES
		PUBLIC_HEADER "grid_client.h"
		SOVERSION ${ABI_VERSION})

target_link_libraries(gridclient
		metautils metacomm gridcluster
		meta2remote meta2servicesremote meta0remote meta1remote
		meta0utils meta2v2utils meta2v2remote
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES})


add_executable(test_include test_include.c)
target_link_libraries(test_include gridclient)

add_executable(test_url test_url.c)
target_link_libraries(test_url gridclient)

install(TARGETS
		gridclient
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

add_test(NAME client/lib/inc COMMAND test_include)
add_test(NAME client/lib/url COMMAND test_url)

