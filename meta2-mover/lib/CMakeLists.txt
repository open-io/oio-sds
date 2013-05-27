include_directories(BEFORE .
		../../metautils/lib
		../../libdbaccess/lib
		../../client/c/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events
		../../meta0v2
		../../meta1v2
		../../meta2/remote)

include_directories(AFTER
		${NEON_INCLUDE_DIRS}
		${GLIB2_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/../../meta2/remote)

add_library(meta2mover SHARED
		meta2_mover.c
		meta2_mover.h
		meta2_mover_internals.h
		meta2_mover_lb.c
		meta2_mover_utils.c
)

set_target_properties(meta2mover PROPERTIES
		SOVERSION ${ABI_VERSION})

target_link_libraries(meta2mover
		metautils metacomm
		meta2remote meta2servicesremote meta0remote meta1remote
		gridcluster gridclient
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS
		meta2mover 
		LIBRARY DESTINATION ${LD_LIBDIR})

