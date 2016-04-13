add_definitions(-DG_LOG_DOMAIN="oio.events")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

include_directories(AFTER
		${ZMQ_INCLUDE_DIRS})

link_directories(
		${ZMQ_LIBRARY_DIRS})


add_library(oioevents SHARED
	oio_events_queue.c
	oio_events_queue_buffer.c
	oio_events_queue_zmq.c
	oio_events_queue_beanstalkd.c)

set_target_properties(oioevents PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(oioevents metautils ${GLIB2_LIBRARIES} ${ZMQ_LIBRARIES})

install(TARGETS oioevents
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin
		PUBLIC_HEADER DESTINATION include)


