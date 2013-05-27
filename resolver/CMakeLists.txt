include_directories(BEFORE .
		../metautils/lib
		../cluster/lib
		../cluster/agent
		../cluster/events)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

add_library(hcresolve SHARED
		hc_resolve.c
		hc_resolver.c
		hc_resolver_internals.h
		hc_resolver.h)

target_link_libraries(hcresolve
		meta0remote meta1remote metautils metacomm gridcluster
		${GLIB2_LIBRARIES})


install(TARGETS hcresolve
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

