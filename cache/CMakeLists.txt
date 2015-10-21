add_definitions(-DG_LOG_DOMAIN="oio.cache")

include_directories(BEFORE . ..)

add_library(oiocache SHARED cache.c cache_noop.c cache_lru.c)
target_link_libraries(oiocache metautils ${GLIB2_LIBRARIES})

install(TARGETS oiocache 
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin
		PUBLIC_HEADER DESTINATION include)

add_executable(test_cache_abstract test_cache_abstract.c)
target_link_libraries(test_cache_abstract oiocache)

add_test(NAME cache/abstract COMMAND test_cache_abstract)

