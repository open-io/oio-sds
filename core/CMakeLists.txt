add_definitions(-DG_LOG_DOMAIN="oio.core")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_library(oiocore SHARED url.c cfg.c str.c ext.c log.c lb.c)
target_link_libraries(oiocore
		${JSONC_LIBRARIES} ${GLIB2_LIBRARIES})
set_target_properties(oiocore PROPERTIES
		PUBLIC_HEADER "oio_core.h"
		SOVERSION ${ABI_VERSION})

add_library(oiosds SHARED sds.c proxy.c headers.c http_put.c dir.c cs.c)
target_link_libraries(oiosds oiocore
		${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES})
set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

add_executable(tool_roundtrip tool_roundtrip.c)
target_link_libraries(tool_roundtrip oiosds)

add_executable(tool_config tool_config.c)
target_link_libraries(tool_config oiosds)

add_executable(tool_ns tool_ns.c)
target_link_libraries(tool_ns oiosds ${CURL_LIBRARIES})

install(FILES
		oiocfg.h
		oiodir.h
		oioext.h
		oiolog.h
		oiostr.h
		oiourl.h
		oiocs.h
		oiolb.h
		DESTINATION include/core)

install(TARGETS oiocore oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

