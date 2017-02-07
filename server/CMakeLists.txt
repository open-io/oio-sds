add_definitions(-DG_LOG_DOMAIN="oio.srv")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

add_library(server SHARED
		internals.h
		slab.c slab.h
		network_server.c network_server.h
        transport_gridd.c transport_gridd.h)

set_target_properties(server PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(server
		metautils
		-lm ${GLIB2_LIBRARIES})

install(TARGETS server
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

