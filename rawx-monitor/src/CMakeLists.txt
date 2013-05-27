include_directories(BEFORE .
		../../metautils/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events)

include_directories(AFTER ${GRIDINIT_INCDIR})

link_directories(${GRIDINIT_LIBDIR})

add_executable(rawx-monitor
	filer_monitor.h
	enterprises.c
	main.c
	snmp.c)

target_link_libraries(rawx-monitor
	metautils gridcluster gridcluster-remote gridcluster-events
	-lgridinit-utils -lm -lnetsnmp ${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS rawx-monitor
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

install(TARGETS rawx-monitor
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin
	PUBLIC_HEADER DESTINATION include
)
