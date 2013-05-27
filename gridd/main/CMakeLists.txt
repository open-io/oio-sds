include_directories(BEFORE .
		../../metautils/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events)

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
target_link_libraries(gridd
		metautils metacomm gridcluster gridcluster-events gridcluster-remote
		${GLIB2_LIBRARIES})

install(TARGETS gridd
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

