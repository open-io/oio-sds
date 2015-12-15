add_definitions(-DG_LOG_DOMAIN="oio.tests.func")

include_directories(BEFORE . ../..)

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

if (HIREDIS_FOUND)
	add_executable(test_cache_redis test_cache_redis.c)
	target_link_libraries(test_cache_redis oiocache oiocache_redis)
	add_test(NAME cache/redis COMMAND test_cache_redis)
endif ()

if (LIBMEMCACHED_FOUND)
	add_executable(test_cache_memcached test_cache_memcached.c)
	target_link_libraries(test_cache_memcached oiocache oiocache_memcached)
	add_test(NAME cache/memcached COMMAND test_cache_memcached)
endif ()

add_library(oiosds_test SHARED testlib_sds.c)
target_link_libraries(oiosds_test oiosds)
set_target_properties(oiosds_test PROPERTIES
		SOVERSION ${ABI_VERSION})
add_test(NAME core/sds
		COMMAND /usr/bin/env python ${CMAKE_CURRENT_SOURCE_DIR}/test_oiosds.py ${CMAKE_CURRENT_BINARY_DIR})

add_library(oiohttp_test SHARED testlib_http.c)
target_link_libraries(oiohttp_test oiosds)
set_target_properties(oiohttp_test PROPERTIES
		SOVERSION ${ABI_VERSION})
add_test(NAME core/http
		COMMAND /usr/bin/env python ${CMAKE_CURRENT_SOURCE_DIR}/test_oiohttp.py ${CMAKE_CURRENT_BINARY_DIR})

add_executable(test_oio_dir test_dir.c)
target_link_libraries(test_oio_dir oiosds)
add_test(NAME core/dir COMMAND test_oio_dir)

add_executable(test_sqlx_client test_sqlx_client.c)
target_link_libraries(test_sqlx_client
		oiosqlx oiosqlx_direct oiosqlx_local)
add_test(NAME sqlx/client COMMAND test_sqlx_client)

