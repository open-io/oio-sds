#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${ZK_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(sqlxsrv SHARED
		sqlx_service.c sqlx_service.h)

set_target_properties(sqlxsrv PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(sqlxsrv
		server metautils gridcluster sqliterepo
		hcresolve meta0remote meta1remote
		server sqliterepo metautils metacomm gridcluster
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


add_executable(hcsqlx sqlx_client.c)
bin_prefix(hcsqlx -sqlx)
bin_prefix_full(hcsqlx -sqlx-client)
target_link_libraries(hcsqlx
		gridclient metautils metacomm gridcluster sqlitereporemote
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})
		

add_executable(sqlx_server sqlx_server.c)
bin_prefix_full(sqlx_server -sqlx-server)
target_link_libraries(sqlx_server
		sqlxsrv ${GLIB2_LIBRARIES})


install(TARGETS sqlx_server hcsqlx sqlxsrv
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

