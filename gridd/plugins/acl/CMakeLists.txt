include_directories(BEFORE .
		../../../metautils/lib
		../../gridd/main
		../../../cluster/lib
		../../../cluster/agent
		../../../cluster/events)

add_library(acl MODULE acl.c)
set_target_properties(acl PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(acl metautils metacomm gridcluster ${GLIB2_LIBRARIES})
install(TARGETS acl 
        LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY}
        RUNTIME DESTINATION bin)

