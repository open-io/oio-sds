add_definitions(-DG_LOG_DOMAIN="oio.sqlx")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_BINARY_DIR}/metautils/asn1c
		${CMAKE_BINARY_DIR}/metautils/lib)

include_directories(AFTER
		${ZK_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(sqlxsrv STATIC sqlx_service.c)

target_link_libraries(sqlxsrv
		server metautils gridcluster sqliterepo
		hcresolve meta0remote meta1remote
		server sqliterepo metautils gridcluster
		oioevents
		${GLIB2_LIBRARIES})

