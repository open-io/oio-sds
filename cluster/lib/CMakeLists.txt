add_definitions(-DG_LOG_DOMAIN="oio.cluster.lib")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR})

add_library(gridcluster SHARED gridcluster.c)
set_target_properties(gridcluster PROPERTIES VERSION 0.0.0 SOVERSION 0)
target_link_libraries(gridcluster
		metautils oiosds
		${GLIB2_LIBRARIES}
		-lm)

install(TARGETS gridcluster
	LIBRARY DESTINATION ${LD_LIBDIR}
	RUNTIME DESTINATION bin)

