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

add_executable(grid_daemon_test grid_daemon_test.c)
target_link_libraries(grid_daemon_test
		server metautils
		${GLIB2_LIBRARIES})

add_executable(test_stats_holder test_stats_holder.c)
target_link_libraries(test_stats_holder server
        ${GLIB2_LIBRARIES})

install(TARGETS
			server 
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

