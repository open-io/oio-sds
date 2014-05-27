#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_definitions(-Dyylex=event_yylex)

add_custom_command(
	OUTPUT cfg.yacc.c cfg.yacc.h
	COMMAND ${BISON_EXECUTABLE}
	ARGS -d -y -p event_yy -o cfg.yacc.c ${CMAKE_CURRENT_SOURCE_DIR}/cfg.yacc.y
)

add_library(gridcluster-events SHARED
		${CMAKE_CURRENT_BINARY_DIR}/cfg.yacc.c
		${CMAKE_CURRENT_BINARY_DIR}/cfg.yacc.h
		eventhandler.c events.c events_repo.c
		eventhandler_internals.h
		gridcluster_eventhandler.h
		gridcluster_events.h)
target_link_libraries(gridcluster-events
		metautils metacomm
		-lm ${GLIB2_LIBRARIES})
set_target_properties(gridcluster-events PROPERTIES SOVERSION ${ABI_VERSION})


add_library(gridcluster-eventsremote SHARED
		gridcluster_eventsremote.h
		events_remote.c)
target_link_libraries(gridcluster-eventsremote
		metautils metacomm
		${GLIB2_LIBRARIES})
set_target_properties(gridcluster-eventsremote PROPERTIES SOVERSION ${ABI_VERSION})
add_dependencies(gridcluster-eventsremote gridcluster-events)


add_executable(test_parser test_parser.c)
target_link_libraries(test_parser
		gridcluster-events metautils
		${GLIB2_LIBRARIES})
add_dependencies(test_parser gridcluster_client)

install(FILES
			gridcluster_events.h
			gridcluster_eventhandler.h
			gridcluster_eventsremote.h
		DESTINATION include/cluster/events
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS gridcluster-events gridcluster-eventsremote
		LIBRARY DESTINATION ${LD_LIBDIR})

