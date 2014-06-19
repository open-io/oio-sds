set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

include_directories(BEFORE . .. ../..)

add_executable(gridd
		internal_alerts.h
		message_handler.c message_handler.h
		plugin.c plugin.h
		plugin_holder.h
		server.c
		server_internals.h
		sock.c sock.h
		srvalert.c srvalert.h
		srvstats.h
		srvtimer.h
		statistics.c
		timer.c
		access_log.c
)
bin_prefix_full(gridd -daemon)
target_link_libraries(gridd
		metautils metacomm gridcluster gridcluster-events gridcluster-remote
		${GLIB2_LIBRARIES})

install(FILES
			message_handler.h
			plugin.h
			plugin_holder.h
			srvalert.h
			srvstats.h
			srvtimer.h
		DESTINATION include/gridd/main
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS gridd
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

