add_definitions(-DG_LOG_DOMAIN="oio.srv")

include_directories(BEFORE . ..)

add_library(server SHARED
		internals.h
		slab.c slab.h
		network_server.c network_server.h
        transport_gridd.c transport_gridd.h
		grid_daemon.c grid_daemon.h
		stats_holder.c stats_holder.h)

set_target_properties(server PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(server
		metautils
		-lm ${GLIB2_LIBRARIES})

install(TARGETS server
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

