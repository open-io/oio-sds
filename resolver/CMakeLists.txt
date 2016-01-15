add_definitions(-DG_LOG_DOMAIN="oio.resolver")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

include_directories(AFTER
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

add_library(hcresolve SHARED
		hc_resolver.c)

target_link_libraries(hcresolve
		meta0remote meta1remote metautils gridcluster
		${GLIB2_LIBRARIES})

install(TARGETS hcresolve
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

