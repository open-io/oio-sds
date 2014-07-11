#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../..)

include_directories(AFTER
		${GRIDINIT_INCDIR}
		${ONTAP_INCDIR})

link_directories(
		${GRIDINIT_LIBDIR}
		${ONTAP_LIBDIR})

add_executable(rawx-monitor
	filer_monitor.h
	enterprises.c
	main.c
	snmp.c)

bin_prefix(rawx-monitor -rawx-monitor)

target_link_libraries(rawx-monitor
	metautils gridcluster gridcluster-remote gridcluster-events
	-lgridinit-utils -lm -lnetsnmp ${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS rawx-monitor
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin
	PUBLIC_HEADER DESTINATION include)

