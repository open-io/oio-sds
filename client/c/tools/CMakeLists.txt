include_directories(BEFORE .
		../../..
		${CMAKE_CURRENT_BINARY_DIR}/../../..
		../../../metautils/lib)

set(REQLIBS
		gridclient metautils metacomm
		gridcluster gridcluster-remote gridcluster-events
		meta2remote meta1remote meta0remote
		${GLIB2_LIBRARIES})

set(SOLRLIBS solrutils)

macro(bin_prefix_local T N)
	target_link_libraries(${T} ${REQLIBS})
	if (DEFINED EXE_PREFIX)
	set_target_properties(${T} PROPERTIES OUTPUT_NAME ${EXE_PREFIX}${N})
	else()
	set_target_properties(${T} PROPERTIES OUTPUT_NAME gs${N})
	endif()
endmacro(bin_prefix_local)

add_executable(gsv2_add_event gs_add_event.c)
bin_prefix_local(gsv2_add_event _add_event)

add_executable(gsv2_append gs_append.c gs_tools.c)
bin_prefix_local(gsv2_append _append)

add_executable(gsv2_create gs_create.c gs_tools.c)
bin_prefix_local(gsv2_create _create)

add_executable(gsv2_destroy gs_destroy.c gs_tools.c)
bin_prefix_local(gsv2_destroy _destroy)

add_executable(gsv2_get gs_get.c gs_tools.c)
bin_prefix_local(gsv2_get _get)

add_executable(gsv2_get_all gs_get_all.c)
bin_prefix_local(gsv2_get_all _get_all)

add_executable(gsv2_index gs_index.c)
bin_prefix_local(gsv2_index _index)

add_executable(gsv2_list_events gs_list_events.c)
bin_prefix_local(gsv2_list_events _list_events)

add_executable(gsv2_list_prop gs_list_prop.c gs_tools.c)
bin_prefix_local(gsv2_list_prop _list_prop)

add_executable(gsv2_locate gs_locate.c gs_tools.c)
bin_prefix_local(gsv2_locate _locate)

add_executable(gsv2_ls gs_ls.c gs_tools.c)
bin_prefix_local(gsv2_ls _ls)

add_executable(gsv2_put gs_put.c gs_tools.c)
bin_prefix_local(gsv2_put _put)

add_executable(gsv2_rm gs_rm.c gs_tools.c)
bin_prefix_local(gsv2_rm _rm)

add_executable(gsv2_rm_prop gs_rm_prop.c gs_tools.c) 
bin_prefix_local(gsv2_rm_prop _rm_prop)

add_executable(gsv2_set_prop gs_set_prop.c gs_tools.c)
bin_prefix_local(gsv2_set_prop _set_prop)

add_executable(gsv2_touch gs_touch.c)
bin_prefix_local(gsv2_touch _touch)

add_executable(gsv2_rm_event gs_rm_event.c)
bin_prefix_local(gsv2_rm_event _rm_event)

add_executable(gsv2_quota gs_quota.c)
bin_prefix_local(gsv2_quota _quota)


add_executable(gsv2_unref_solr gs_unref_solr.c)
bin_prefix_local(gsv2_unref_solr _unref_solr)
target_link_libraries(gsv2_unref_solr ${SOLRLIBS})

add_executable(gsv2_set_solr gs_set_solr.c)
bin_prefix_local(gsv2_set_solr _set_solr)
target_link_libraries(gsv2_set_solr ${SOLRLIBS})


add_executable(test_upload test_upload.c)
target_link_libraries(test_upload ${REQLIBS})


add_executable(hcdir hcdir.c)
bin_prefix(hcdir "-dir")
target_link_libraries(hcdir ${REQLIBS})

add_executable(hc hc.c)
bin_prefix(hc "")
target_link_libraries(hc ${REQLIBS})

add_executable(hcadmin hcadmin.c)
bin_prefix(hcadmin "-admin")
target_link_libraries(hcadmin ${REQLIBS})


if (NOT DEFINED FULL_RENAME)
if (NOT DEFINED EXE_PREFIX)
install(TARGETS
			gsv2_touch
			gsv2_set_prop
			gsv2_rm_prop
			gsv2_rm
			gsv2_put
			gsv2_ls
			gsv2_locate
			gsv2_list_prop
			gsv2_list_events
			gsv2_rm_event
			gsv2_index
			gsv2_get
			gsv2_get_all
			gsv2_destroy
			gsv2_create
			gsv2_append
			gsv2_add_event
			gsv2_unref_solr
			gsv2_set_solr
			gsv2_quota
		RUNTIME DESTINATION bin)
endif()
endif()

install(TARGETS hcdir hc hcadmin
		RUNTIME DESTINATION bin)

