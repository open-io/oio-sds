add_definitions(-DG_LOG_DOMAIN="oio.sqlite")

include_directories(BEFORE . ..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils)

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

add_executable(test_repository test_repository.c)
target_link_libraries(test_repository sqliterepo sqlitereporemote
		metautils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(test_sqliterepo test_sqliterepo.c)
target_link_libraries(test_sqliterepo sqliterepo sqlitereporemote
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_version test_version.c)
target_link_libraries(test_version sqliterepo 
		metautils
		${GLIB2_LIBRARIES})

add_executable(gs_m1hash hash.h gs_m1hash.c)
bin_prefix(gs_m1hash -m1hash)
target_link_libraries(gs_m1hash
		metautils sqliterepo
		${GLIB2_LIBRARIES})

install(TARGETS
			sqliteutils
			sqlitereporemote
			sqliterepo
			gs_m1hash
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

