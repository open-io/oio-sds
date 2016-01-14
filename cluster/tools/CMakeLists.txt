add_definitions(-DG_LOG_DOMAIN="oio.cluster.tools")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_executable(gridcluster_cli gridcluster.c)
set_target_properties(gridcluster_cli PROPERTIES OUTPUT_NAME gridcluster)
bin_prefix(gridcluster_cli -cluster)
target_link_libraries(gridcluster_cli
		gridcluster metautils
		${GLIB2_LIBRARIES})

install(TARGETS
		gridcluster_cli
	RUNTIME DESTINATION bin)

