#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../..)

include_directories(AFTER
		${NETSNMP_INCLUDE_DIRS}
		${NEON_INCLUDE_DIRS})

link_directories(
		${NETSNMP_LIBRARY_DIRS}
		${NEON_LIBRARY_DIRS})

add_library(netsnmpd_grid_storage MODULE
	idx_management.h idx_management.c
	session.h session.c
	events.h events.c
	grid_storage.h grid_storage.c)

set_target_properties(netsnmpd_grid_storage
		PROPERTIES
			PREFIX ""
			OUTPUT_NAME grid_storage)

target_link_libraries(netsnmpd_grid_storage
		metautils gridcluster statsclient
		${NEON_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS netsnmpd_grid_storage
		LIBRARY DESTINATION ${LD_LIBDIR}/snmp)

