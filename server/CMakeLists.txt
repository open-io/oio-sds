include_directories(BEFORE .
		../metautils/lib)

add_library(server SHARED
		internals.h
		slab.c slab.h
		network_server.c network_server.h
        transport_echo.c transport_echo.h
        transport_gridd.c transport_gridd.h
        transport_http.c transport_http.h
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
        network_server_echo.c)
target_link_libraries(network_server_echo
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(network_server_static
        network_server_static.c)
target_link_libraries(network_server_static
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(network_server_http
        network_server_http.c)
target_link_libraries(network_server_http
		server metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(grid_daemon_test grid_daemon_test.c)
target_link_libraries(grid_daemon_test
		server metautils metacomm
		${GLIB2_LIBRARIES})

install(TARGETS server 
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

