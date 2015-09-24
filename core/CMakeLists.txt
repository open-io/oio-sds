add_definitions(-DG_LOG_DOMAIN="oio.core")

include_directories(BEFORE . ..)

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_library(oiocore SHARED url.c cfg.c str.c ext.c log.c)
target_link_libraries(oiocore
		${JSONC_LIBRARIES} ${GLIB2_LIBRARIES})
set_target_properties(oiocore PROPERTIES
		PUBLIC_HEADER "oio_core.h"
		SOVERSION ${ABI_VERSION})

add_library(oiosds SHARED sds.c http_put.c)
target_link_libraries(oiosds oiocore
		${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES})
set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

add_executable(test_oio_str test_str.c)
target_link_libraries(test_oio_str oiocore)

add_executable(test_oio_url test_url.c)
target_link_libraries(test_oio_url oiocore)

add_executable(test_roundtrip test_roundtrip.c)
target_link_libraries(test_roundtrip oiosds)

add_executable(test_config test_config.c)
target_link_libraries(test_config oiosds)

add_executable(test_ns test_ns.c)
target_link_libraries(test_ns oiosds ${CURL_LIBRARIES})

install(FILES
		oiocfg.h
		oioext.h
		oiolog.h
		oiostr.h
		oiourl.h
		DESTINATION include/core)

install(TARGETS oiocore oiosds
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

add_test(NAME metautils/url COMMAND test_hc_url)
add_test(NAME core/str COMMAND test_oio_str)

