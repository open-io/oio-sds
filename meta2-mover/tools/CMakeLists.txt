include_directories(BEFORE .
		../../metautils/lib
		../../libdbaccess/lib
		../../client/c/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events
		../../meta0v2
		../../meta1v2
		../../meta2/remote
		../lib)

include_directories(AFTER
		${CMAKE_CURRENT_BINARY_DIR}/../../meta2/remote)

add_executable(redc-meta2-mover
		gs_meta2_mover.c)

target_link_libraries(redc-meta2-mover
		meta2mover metautils metacomm meta2remote meta1remote
		gridcluster
		${GLIB2_LIBRARIES})

install(TARGETS redc-meta2-mover RUNTIME DESTINATION bin)
