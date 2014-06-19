include_directories(BEFORE . ../.. ../../..)

add_library(statsclient SHARED stats_remote.c stats_remote.h)
set_target_properties(statsclient PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(statsclient metautils metacomm ${GLIB2_LIBRARIES})

add_executable(gridc_stats client_stats.c stats_remote.c stats_remote.h)
bin_prefix(gridc_stats -gridc-stats)
bin_prefix_full(gridc_stats -utils-stats)
target_link_libraries(gridc_stats metautils metacomm statsclient)
add_dependencies(gridc_stats statsclient)

install(TARGETS statsclient gridc_stats
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

