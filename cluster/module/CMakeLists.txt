add_definitions(-DG_LOG_DOMAIN="oio.cluster.module")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)
include_directories(AFTER ${ZMQ_INCLUDE_DIRS})
link_directories(${ZMQ_LIBRARY_DIRS})

add_library(msg_conscience MODULE module.c)
set_target_properties(msg_conscience PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(msg_conscience metautils
		gridcluster gridcluster-conscience
		${GLIB2_LIBRARIES} ${ZMQ_LIBRARIES})

install(TARGETS msg_conscience
		LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY})

