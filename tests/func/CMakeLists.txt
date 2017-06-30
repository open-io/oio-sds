add_definitions(-DG_LOG_DOMAIN="oio.tests.func")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

if (DEFINED ALLOW_HIREDIS)
	if (HIREDIS_FOUND)
		add_executable(test_cache_redis test_cache_redis.c)
		target_link_libraries(test_cache_redis oiocache oiocache_redis)
		add_test(NAME cache/redis COMMAND test_cache_redis)
	endif ()
endif ()

if (DEFINED ALLOW_LIBMEMCACHED)
	if (LIBMEMCACHED_FOUND)
		add_executable(test_cache_memcached test_cache_memcached.c)
		target_link_libraries(test_cache_memcached oiocache oiocache_memcached)
		add_test(NAME cache/memcached COMMAND test_cache_memcached)
	endif ()
endif ()

add_library(oiosds_test SHARED testlib_sds.c)
target_link_libraries(oiosds_test oiosds)
set_target_properties(oiosds_test PROPERTIES
		SOVERSION ${ABI_VERSION})
add_test(NAME core/sds
		COMMAND /usr/bin/env ${PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/test_oiosds.py ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(core/sds PROPERTIES ENVIRONMENT CTEST_OUTPUT_ON_FAILURE=1)

add_library(oiohttp_test SHARED testlib_http.c)
target_link_libraries(oiohttp_test oiosds)
set_target_properties(oiohttp_test PROPERTIES
		SOVERSION ${ABI_VERSION})
add_test(NAME core/http
		COMMAND /usr/bin/env ${PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/test_oiohttp.py ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(core/http PROPERTIES ENVIRONMENT CTEST_OUTPUT_ON_FAILURE=1)

add_executable(test_oio_cs test_cs.c)
target_link_libraries(test_oio_cs oiosds)
add_test(NAME core/cs COMMAND test_oio_cs)

add_executable(test_oio_cluster test_cluster.c)
target_link_libraries(test_oio_cluster oiocore gridcluster)
add_test(NAME cluster/lib COMMAND test_oio_cluster)

add_executable(test_oio_dir test_dir.c)
target_link_libraries(test_oio_dir oiosds)
add_test(NAME core/dir COMMAND test_oio_dir)

add_executable(test_sqlx_client_sds test_sqlx_client.c)
target_link_libraries(test_sqlx_client_sds oiosqlx oiosqlx_direct ${COMMON})
add_test(NAME sqlx/client/sds COMMAND test_sqlx_client_sds)

add_executable(test_weird_chars test_weird_chars.c)
target_link_libraries(test_weird_chars oiosds oiocore)
add_test(NAME core/sds/weird_chars COMMAND test_weird_chars)
