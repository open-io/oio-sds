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

add_library(oiosds SHARED sds.c proxy.c headers.c http_put.c)
target_link_libraries(oiosds oiocore
		${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES})
set_target_properties(oiosds PROPERTIES
		PUBLIC_HEADER "oio_sds.h"
		SOVERSION ${ABI_VERSION})

add_library(oiosds_test SHARED testlib_sds.c)
target_link_libraries(oiosds_test oiosds)
set_target_properties(oiosds_test PROPERTIES
		SOVERSION ${ABI_VERSION})

add_library(oiohttp_test SHARED testlib_http.c)
target_link_libraries(oiohttp_test oiosds)
set_target_properties(oiohttp_test PROPERTIES
		SOVERSION ${ABI_VERSION})

add_executable(test_oio_ext test_ext.c)
target_link_libraries(test_oio_ext oiocore)

add_executable(test_oio_str test_str.c)
target_link_libraries(test_oio_str oiocore)

add_executable(test_oio_url test_url.c)
target_link_libraries(test_oio_url oiocore)

add_executable(tool_roundtrip tool_roundtrip.c)
target_link_libraries(tool_roundtrip oiosds)

add_executable(tool_config tool_config.c)
target_link_libraries(tool_config oiosds)

add_executable(tool_ns tool_ns.c)
target_link_libraries(tool_ns oiosds ${CURL_LIBRARIES})

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

add_test(NAME core/ext COMMAND test_oio_ext)
add_test(NAME core/url COMMAND test_oio_url)
add_test(NAME core/str COMMAND test_oio_str)
add_test(NAME core/http COMMAND /usr/bin/env python ${CMAKE_CURRENT_SOURCE_DIR}/test_oiohttp.py ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME core/sds COMMAND /usr/bin/env python ${CMAKE_CURRENT_SOURCE_DIR}/test_oiosds.py ${CMAKE_CURRENT_BINARY_DIR})

