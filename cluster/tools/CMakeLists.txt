
include_directories(BEFORE .
		../../metautils/lib
		../events ../conscience ../remote ../lib ../agent)

add_executable(gridcluster_cli
		gridcluster.c)
set_target_properties(gridcluster_cli PROPERTIES OUTPUT_NAME gridcluster)
target_link_libraries(gridcluster_cli
		gridcluster gridcluster-events gridcluster-eventsremote gridcluster-remote
		metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(gridcluster_event
	gridcluster_event.c)
target_link_libraries(gridcluster_event
	gridcluster gridcluster-events gridcluster-remote gridcluster-eventsremote
	metautils metacomm
	${GLIB2_LIBRARIES})

add_executable(gridcluster_dummy_service
	dummy_service.c)
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

