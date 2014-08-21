include_directories(BEFORE . .. ../..)

add_library(gridcluster-remote SHARED
		gridcluster_remote.c gridcluster_remote.h)
set_target_properties(gridcluster-remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(gridcluster-remote
		metautils metacomm gridcluster-eventsremote
		-lm ${GLIB2_LIBRARIES})

install(FILES
			gridcluster_remote.h
		DESTINATION include/cluster/remote
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS gridcluster-remote
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

