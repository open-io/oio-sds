include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/..)

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_library(oiosds SHARED oio_sds.c http_put.c)

target_link_libraries(oiosds
		metautils gridcluster
		${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES})

set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

add_executable(test_sdk test_sdk.c)
target_link_libraries(test_sdk oiosds)

add_executable(oio_config oio_config.c)
target_link_libraries(oio_config oiosds)

install(TARGETS
			oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

