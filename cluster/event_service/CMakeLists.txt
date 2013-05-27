include_directories(BEFORE .
		../../metautils/lib
		../../libdbaccess/lib
		../../gridd/main
		../lib ../agent ../events ../conscience)

add_library(msg_event_service MODULE module.c skeleton.c event_service_internals.h)
set_target_properties(msg_event_service PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(msg_event_service
		metautils metacomm gridcluster-events
		${GLIB2_LIBRARIES})

install(TARGETS msg_event_service
		LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY})

