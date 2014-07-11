include_directories(BEFORE . ../.. ../../..)

add_executable(gridc_ping action.c)
bin_prefix(gridc_ping -gridc-ping)
bin_prefix_full(gridc_ping -utils-ping)
target_link_libraries(gridc_ping metautils metacomm
		${GLIB2_LIBRARIES})

install(TARGETS gridc_ping
		RUNTIME DESTINATION bin)

