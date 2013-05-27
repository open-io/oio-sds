include_directories(BEFORE .
		../../../metautils/lib
		../../main)

add_executable(gridc_ping action.c)
target_link_libraries(gridc_ping metautils metacomm
		${GLIB2_LIBRARIES})

install(TARGETS gridc_ping
		RUNTIME DESTINATION bin)

