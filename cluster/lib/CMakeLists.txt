add_definitions(-DG_LOG_DOMAIN="oio.cluster.lib")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_library(gridcluster SHARED
		gridcluster.c
		message.c)

set_target_properties(gridcluster PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(gridcluster
		metautils oiosds
		-lm ${GLIB2_LIBRARIES})

add_executable (tool_sysstat tool_sysstat.c)
target_link_libraries (tool_sysstat gridcluster)

install(TARGETS gridcluster
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

