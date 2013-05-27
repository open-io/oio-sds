include_directories(BEFORE .
		../../../metautils/lib
		../../../libdbaccess/lib
		../../../cluster/lib ../../../cluster/agent ../../../cluster/events
		../../../meta1v2
		../../../meta0v2
		../../../meta2/remote
		../../../meta2v2
		../lib)

include_directories(AFTER
		${CMAKE_CURRENT_BINARY_DIR}/../../../meta2/remote
		${CMAKE_CURRENT_BINARY_DIR}/../../../meta2v2)

set(BINPREFIX redc_)

set(REQLIBS
		gridclient metautils metacomm
		gridcluster gridcluster-remote gridcluster-events
		meta2remote meta1remote meta0remote
		${GLIB2_LIBRARIES})

add_executable(${BINPREFIX}add_event gs_add_event.c)
target_link_libraries(${BINPREFIX}add_event ${REQLIBS})

add_executable(${BINPREFIX}append gs_append.c gs_tools.c)
target_link_libraries(${BINPREFIX}append ${REQLIBS})

add_executable(${BINPREFIX}create gs_create.c gs_tools.c)
target_link_libraries(${BINPREFIX}create ${REQLIBS})

add_executable(${BINPREFIX}destroy gs_destroy.c gs_tools.c)
target_link_libraries(${BINPREFIX}destroy ${REQLIBS})

add_executable(${BINPREFIX}get gs_get.c gs_tools.c)
target_link_libraries(${BINPREFIX}get ${REQLIBS})

add_executable(${BINPREFIX}get_all gs_get_all.c)
target_link_libraries(${BINPREFIX}get_all ${REQLIBS})

add_executable(${BINPREFIX}index gs_index.c)
target_link_libraries(${BINPREFIX}index ${REQLIBS})

add_executable(${BINPREFIX}list_events gs_list_events.c)
target_link_libraries(${BINPREFIX}list_events ${REQLIBS})

add_executable(${BINPREFIX}list_prop gs_list_prop.c gs_tools.c)
target_link_libraries(${BINPREFIX}list_prop ${REQLIBS})

add_executable(${BINPREFIX}locate gs_locate.c gs_tools.c)
target_link_libraries(${BINPREFIX}locate ${REQLIBS})

add_executable(${BINPREFIX}ls gs_ls.c gs_tools.c)
target_link_libraries(${BINPREFIX}ls ${REQLIBS})

add_executable(${BINPREFIX}put gs_put.c gs_tools.c)
target_link_libraries(${BINPREFIX}put ${REQLIBS})

add_executable(${BINPREFIX}rm gs_rm.c gs_tools.c)
target_link_libraries(${BINPREFIX}rm ${REQLIBS})

add_executable(${BINPREFIX}rm_prop gs_rm_prop.c gs_tools.c) 
target_link_libraries(${BINPREFIX}rm_prop ${REQLIBS})

add_executable(${BINPREFIX}set_prop gs_set_prop.c gs_tools.c)
target_link_libraries(${BINPREFIX}set_prop ${REQLIBS})

add_executable(${BINPREFIX}touch gs_touch.c)
target_link_libraries(${BINPREFIX}touch ${REQLIBS})

add_executable(${BINPREFIX}rm_event gs_rm_event.c)
target_link_libraries(${BINPREFIX}rm_event ${REQLIBS})

add_executable(redcdir hcdir.c)
target_link_libraries(redcdir ${REQLIBS})

add_executable(redc hc.c)
target_link_libraries(redc ${REQLIBS})

add_executable(${BINPREFIX}quota gs_quota.c)
target_link_libraries(${BINPREFIX}quota ${REQLIBS})

#install(TARGETS
#			${BINPREFIX}touch
#			${BINPREFIX}set_prop
#			${BINPREFIX}rm_prop
#			${BINPREFIX}rm
#			${BINPREFIX}put
#			${BINPREFIX}ls
#			${BINPREFIX}locate
#			${BINPREFIX}list_prop
#			${BINPREFIX}list_events
#			${BINPREFIX}rm_event
#			${BINPREFIX}index
#			${BINPREFIX}get_all gs_get
#			${BINPREFIX}destroy
#			${BINPREFIX}create
#			${BINPREFIX}append
#			${BINPREFIX}add_event
#			${BINPREFIX}quota
#		RUNTIME DESTINATION bin)

install(TARGETS redcdir redc
		RUNTIME DESTINATION bin)
