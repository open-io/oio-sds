include_directories(BEFORE .
		../../../metautils/lib
		../../../libdbaccess/lib
		../../../cluster/lib ../../../cluster/agent ../../../cluster/events
		../../../meta1v2
		../../../meta0v2
		../../../meta2/remote)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${NEON_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/../../../meta2v2)

link_directories(
		${SQLITE3_LIBRARY_DIRS})

add_library(hcclient SHARED
		hc_client_storage.h hc_client_internals.h
		hc_client_storage.c
		hc_client_storage_download.c
		hc_client_storage_upload.c)

target_link_libraries(hcclient
		metautils metacomm hcresolve meta2v2utils
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

set_target_properties(hcclient PROPERTIES
		PUBLIC_HEADER "hc_client_storage.h"
		SOVERSION ${ABI_VERSION})

install(TARGETS hcclient
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

#add_test(NAME client/lib/hcclient COMMAND test_hcclient)

