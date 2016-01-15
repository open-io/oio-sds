add_definitions(-DG_LOG_DOMAIN="oio.gridd.srv")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

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
bin_prefix(gridd -daemon)
target_link_libraries(gridd
		metautils gridcluster
		${GLIB2_LIBRARIES})

install(TARGETS gridd
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

