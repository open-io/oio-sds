add_definitions(-DG_LOG_DOMAIN="oio.client.cli")

include_directories(BEFORE .
		../../..
		${CMAKE_CURRENT_BINARY_DIR}/../../..
		../../../metautils/lib)

set(REQLIBS
		gridclient metautils
		gridcluster gridcluster-remote
		meta2v2remote meta1remote meta0remote
		${GLIB2_LIBRARIES})

set(SOLRLIBS solrutils)

macro(bin_prefix_local T N)
	target_link_libraries(${T} ${REQLIBS})
	bin_prefix(${T} ${N})
endmacro(bin_prefix_local)

add_executable(hcdir hcdir.c hc_help.c)
bin_prefix(hcdir "-dir")
target_link_libraries(hcdir ${REQLIBS})

add_executable(hc hc.c hc_help.c)
bin_prefix(hc "")
target_link_libraries(hc ${REQLIBS})

add_executable(hcadmin hcadmin.c)
bin_prefix(hcadmin "-admin")
target_link_libraries(hcadmin ${REQLIBS})

install(TARGETS hcdir hc hcadmin
		RUNTIME DESTINATION bin)

