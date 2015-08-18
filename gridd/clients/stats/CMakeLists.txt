add_definitions(-DG_LOG_DOMAIN="oio.gridd.cli")

include_directories(BEFORE . ../.. ../../..)

add_library(statsclient SHARED stats_remote.c stats_remote.h)
set_target_properties(statsclient PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(statsclient metautils ${GLIB2_LIBRARIES})

add_executable(gridc_stats client_stats.c stats_remote.c stats_remote.h)
bin_prefix(gridc_stats -gridc-stats)
target_link_libraries(gridc_stats metautils statsclient)
add_dependencies(gridc_stats statsclient)

install(TARGETS statsclient gridc_stats
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

