add_definitions(-DG_LOG_DOMAIN="oio.sqlx")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

include_directories(AFTER
		${ZK_INCLUDE_DIRS}
		${ZMQ_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${ZMQ_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(sqlxsrv SHARED sqlx_service.c oio_events_queue.c)
set_target_properties(sqlxsrv PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqlxsrv
		server metautils gridcluster sqliterepo
		hcresolve meta0remote meta1remote
		server sqliterepo metautils gridcluster
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES} ${ZMQ_LIBRARIES})


add_library(oiosqlx SHARED sqlx_client.c)
set_target_properties(oiosqlx PROPERTIES
		PUBLIC_HEADER "sqlx_client.h"
		SOVERSION ${ABI_VERSION})
target_link_libraries(oiosqlx
		oiocore oiosds
		${GLIB2_LIBRARIES})

add_library(oiosqlx_local SHARED sqlx_client_local.c)
set_target_properties(oiosqlx_local PROPERTIES
		PUBLIC_HEADER "sqlx_client_local.h"
		SOVERSION ${ABI_VERSION})
target_link_libraries(oiosqlx_local
		oiosqlx ${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})


add_library(oiosqlx_direct SHARED sqlx_client_direct.c)
set_target_properties(oiosqlx_direct PROPERTIES
		PUBLIC_HEADER "sqlx_client_direct.h"
		SOVERSION ${ABI_VERSION})
target_link_libraries(oiosqlx_direct
		oiosqlx sqlitereporemote ${GLIB2_LIBRARIES})


add_executable(tool_sqlx tool_sqlx.c)
bin_prefix(tool_sqlx -sqlx)
target_link_libraries(tool_sqlx
		oiocore oiosds oiosqlx_direct
		${GLIB2_LIBRARIES})

add_executable(sqlx_server sqlx_server.c)
bin_prefix(sqlx_server -sqlx-server)
target_link_libraries(sqlx_server
		sqlxsrv ${GLIB2_LIBRARIES})

install(TARGETS
			sqlx_server
			tool_sqlx
			sqlxsrv
			oiosqlx
			oiosqlx_direct
			oiosqlx_local
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin
		PUBLIC_HEADER DESTINATION include)

