add_definitions(-DG_LOG_DOMAIN="oio.sqlx")

include_directories(BEFORE . ..
		../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils)

include_directories(AFTER
		${ZK_INCLUDE_DIRS}
		${ZMQ_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(sqlxsrv SHARED sqlx_service.c)
set_target_properties(sqlxsrv PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqlxsrv
		server metautils gridcluster-remote gridcluster-lb sqliterepo
		hcresolve meta0remote meta1remote
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES} ${ZMQ_LIBRARIES})


add_executable(hcsqlx sqlx_client.c)
bin_prefix(hcsqlx -sqlx)
target_link_libraries(hcsqlx
		metautils gridcluster-remote sqlitereporemote hcresolve
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})
		

add_executable(sqlx_server sqlx_server.c)
bin_prefix(sqlx_server -sqlx-server)
target_link_libraries(sqlx_server
		sqlxsrv ${GLIB2_LIBRARIES})


install(TARGETS
			sqlx_server
			hcsqlx
			sqlxsrv
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

