add_definitions(-DG_LOG_DOMAIN="oio.cluster.module")

include_directories(BEFORE . .. ../..)

add_library(msg_conscience MODULE module.c module.h alerting.h)
set_target_properties(msg_conscience PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(msg_conscience metautils
		gridcluster gridcluster-conscience gridcluster-remote
		${GLIB2_LIBRARIES})

install(TARGETS msg_conscience
		LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY})

