include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/..)

include_directories(AFTER
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_library(oiosds SHARED oio_sds.c)

set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

add_executable(test_sdk test_sdk.c)
target_link_libraries(test_sdk oiosds)

target_link_libraries(oiosds metautils gridclient)

install(TARGETS
			oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

