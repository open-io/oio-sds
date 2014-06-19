include_directories(BEFORE . .. ../..)

add_executable(gridcluster_cli
		gridcluster.c)
set_target_properties(gridcluster_cli PROPERTIES OUTPUT_NAME gridcluster)
bin_prefix(gridcluster_cli -cluster)
bin_prefix_full(gridcluster_cli -cluster)
target_link_libraries(gridcluster_cli
		gridcluster gridcluster-events gridcluster-eventsremote gridcluster-remote
		metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(gridcluster_event
	gridcluster_event.c)
bin_prefix(gridcluster_event -dump-event)
bin_prefix_full(gridcluster_event -cluster-dump-event)
target_link_libraries(gridcluster_event
	gridcluster gridcluster-events gridcluster-remote gridcluster-eventsremote
	metautils metacomm
	${GLIB2_LIBRARIES})

add_executable(gridcluster_dummy_service
	dummy_service.c)
bin_prefix(gridcluster_dummy_service -cluster-register)
target_link_libraries(gridcluster_dummy_service
	gridcluster gridcluster-events gridcluster-eventsremote gridcluster-remote
	metautils metacomm
	${GLIB2_LIBRARIES})

install(
	TARGETS
		gridcluster_cli
		gridcluster_event
		gridcluster_dummy_service
	RUNTIME DESTINATION bin)

