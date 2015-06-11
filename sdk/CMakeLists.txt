include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/..)

include_directories(AFTER
		${NEON_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS})

link_directories(
		${NEON_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS})

add_library(oiosds SHARED oio_sds.c)

set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

target_link_libraries(oiosds metautils gridclient)

install(TARGETS
			oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

