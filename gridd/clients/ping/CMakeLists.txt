add_definitions(-DG_LOG_DOMAIN="oio.gridd.cli")

include_directories(BEFORE . ../.. ../../..)

add_executable(gridc_ping action.c)
bin_prefix(gridc_ping -gridc-ping)
target_link_libraries(gridc_ping metautils
		${GLIB2_LIBRARIES})

install(TARGETS gridc_ping
		RUNTIME DESTINATION bin)

