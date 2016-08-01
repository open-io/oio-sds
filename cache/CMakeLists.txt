add_definitions(-DG_LOG_DOMAIN="oio.cache")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/autogen.h.in ${CMAKE_CURRENT_SOURCE_DIR}/autogen.h)

add_library(oiocache SHARED cache.c cache_noop.c cache_lru.c cache_multilayer.c autogen.h)
target_link_libraries(oiocache metautils ${GLIB2_LIBRARIES})

install(TARGETS oiocache
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin
		PUBLIC_HEADER DESTINATION include)

if (DEFINED ALLOW_HIREDIS)
	if (HIREDIS_FOUND)
		add_library(oiocache_redis SHARED cache_redis.c)
		target_link_libraries(oiocache_redis ${HIREDIS_LIBRARIES})

		install(TARGETS oiocache_redis
				LIBRARY DESTINATION ${LD_LIBDIR}
				RUNTIME DESTINATION bin
				PUBLIC_HEADER DESTINATION include)
	endif ()

endif ()

if (DEFINED ALLOW_LIBMEMCACHED)
	if (LIBMEMCACHED_FOUND)
		add_library(oiocache_memcached SHARED cache_memcached.c)
		target_link_libraries(oiocache_memcached ${LIBMEMCACHED_LIBRARIES})

		install(TARGETS oiocache_memcached
				LIBRARY DESTINATION ${LD_LIBDIR}
				RUNTIME DESTINATION bin
				PUBLIC_HEADER DESTINATION include)
	endif ()
endif ()
