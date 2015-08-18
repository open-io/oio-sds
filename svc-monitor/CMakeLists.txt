add_definitions(-DG_LOG_DOMAIN="oio.mon")

include_directories(BEFORE . ..)

include_directories(AFTER
		${GRIDINIT_INCLUDE_DIRS})

link_directories(
		${SQLITE3_LIBRARY_DIRS}
		${GRIDINIT_LIBRARY_DIRS})

add_executable(svc-monitor main.c)
bin_prefix(svc-monitor -svc-monitor)
target_link_libraries(svc-monitor
		metautils gridcluster
		${GRIDINIT_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS svc-monitor RUNTIME DESTINATION bin)

