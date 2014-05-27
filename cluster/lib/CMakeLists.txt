#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_library(gridcluster SHARED config.c
		connect.c connect.h config.c
		gridcluster.c gridcluster.h
		message.c message.h)

set_target_properties(gridcluster PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(gridcluster
		metautils metacomm gridcluster-remote gridcluster-events
		-lm ${GLIB2_LIBRARIES})

add_executable(gridcluster_test test.c)

target_link_libraries(gridcluster_test
		gridcluster gridcluster-remote gridcluster-events gridcluster-eventsremote
		metautils metacomm
		-lm ${GLIB2_LIBRARIES})

add_dependencies(gridcluster_test gridcluster)

install(FILES
			gridcluster.h
		DESTINATION include/cluster/lib
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS gridcluster
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

