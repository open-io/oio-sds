include_directories(BEFORE .
		../../../metautils/lib
		../lib)

set(REQLIBS
		gridclient metautils
		${GLIB2_LIBRARIES})

add_executable(redc-bench gs_bench.c
	name_generators.c gs_scenarii.c
	create_container_scenario.c set_service_scenario.c
	get_service_scenario.c put_content_scenario.c
	namespace_content.c delete_all_scenario.c get_all_scenario.c
	m2v2_db_convert.c)

target_link_libraries(redc-bench ${REQLIBS})

install(TARGETS
		redc-bench
		RUNTIME DESTINATION bin)

