include_directories(BEFORE . .. ../..)

add_executable(gridcluster_cli
		gridcluster.c)
set_target_properties(gridcluster_cli PROPERTIES OUTPUT_NAME gridcluster)
bin_prefix(gridcluster_cli -cluster)
target_link_libraries(gridcluster_cli
		gridcluster gridcluster-remote
		metautils
		${GLIB2_LIBRARIES})

add_executable(gridcluster_dummy_service
	dummy_service.c)
bin_prefix(gridcluster_dummy_service -cluster-register)
target_link_libraries(gridcluster_dummy_service
		gridcluster gridcluster-remote
		metautils
		${GLIB2_LIBRARIES})

install(
	TARGETS
		gridcluster_cli
		gridcluster_dummy_service
	RUNTIME DESTINATION bin)

