set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

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
		metautils metacomm
		-lm ${GLIB2_LIBRARIES})

add_executable(network_server_devnull
        network_server_devnull.c)
target_link_libraries(network_server_devnull
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(network_server_echo
        transport_echo.c transport_echo.h
        network_server_echo.c)
target_link_libraries(network_server_echo
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(network_server_static
        network_server_static.c)
target_link_libraries(network_server_static
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(grid_daemon_test grid_daemon_test.c)
target_link_libraries(grid_daemon_test
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(test_stats_holder test_stats_holder.c)
target_link_libraries(test_stats_holder server
        ${GLIB2_LIBRARIES})

install(FILES
			grid_daemon.h
			gridd_dispatcher_filters.h
			network_server.h
			slab.h
			transport_gridd.h
		DESTINATION include/server
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS server 
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

