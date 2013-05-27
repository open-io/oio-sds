include_directories(BEFORE .
		../../metautils/lib
		../events ../conscience ../remote ../lib ../agent)


add_library(gridcluster-remote SHARED
		gridcluster_remote.c gridcluster_remote.h)
set_target_properties(gridcluster-remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(gridcluster-remote
		metautils metacomm gridcluster-eventsremote
		-lm ${GLIB2_LIBRARIES})

add_executable(gridcluster_client gridcluster_client.c)
target_link_libraries(gridcluster_client
		gridcluster gridcluster-remote metautils metacomm
		${GLIB2_LIBRARIES})
add_dependencies(gridcluster_client gridcluster-remote)

install(TARGETS gridcluster-remote
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

