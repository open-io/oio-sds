include_directories(BEFORE .
		../metautils/lib
		../cluster/lib
		../cluster/agent
		../cluster/events)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${ZK_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_executable(redc-sqlx
		sqlx_client.c)

target_link_libraries(redc-sqlx
		gridclient metautils metacomm gridcluster sqlitereporemote
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})
		

add_executable(sqlx_server sqlx_server.c)

target_link_libraries(sqlx_server
		hcresolve meta0remote meta1remote
		server sqliterepo metautils metacomm gridcluster
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


install(TARGETS sqlx_server redc-sqlx
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

