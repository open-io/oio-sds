add_definitions(-DG_LOG_DOMAIN="oio.sqlite")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

include_directories(AFTER
		${ZK_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(sqliteutils SHARED
		rc.c
		sqlite_utils.c)

set_target_properties(sqliteutils PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqliteutils metautils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(sqlitereporemote SHARED
		sqlx_remote.c
		sqlx_remote_ex.c
		replication_client.c)

set_target_properties(sqlitereporemote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqlitereporemote metautils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(sqliterepo SHARED
		synchro.c
		version.c
		cache.c
		hash.c
		replication.c
		election.c
		replication_dispatcher.c
		repository.c
		restoration.c
		zk_manager.c
		upgrade.c)

set_target_properties(sqliterepo PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqliterepo metautils
		sqlitereporemote sqliteutils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES} ${ZK_LIBRARIES})

install(TARGETS sqliterepo sqliteutils sqlitereporemote
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

