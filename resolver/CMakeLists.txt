#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

add_library(hcresolve SHARED
		hc_resolve.c
		hc_resolver.c
		hc_resolver_internals.h
		hc_resolver.h)

target_link_libraries(hcresolve
		meta0remote meta1remote metautils metacomm gridcluster
		${GLIB2_LIBRARIES})

install(FILES
			hc_resolver.h
		DESTINATION include/resolver
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS hcresolve
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

