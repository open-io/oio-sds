include_directories(BEFORE .
		../../metautils/lib
		../events ../conscience ../remote ../lib ../agent)

add_library(gridcluster SHARED config.c
		connect.c connect.h
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

install(TARGETS gridcluster
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

