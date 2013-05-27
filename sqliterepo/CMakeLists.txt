include_directories(BEFORE .
		../metautils/lib)
include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${ZK_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})


add_library(sqliteutils SHARED
		rc.c
		sqlite_utils.c
		sqlite_utils.h)

set_target_properties(sqliteutils PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqliteutils metautils 
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(sqlitereporemote SHARED
		sqlx_remote.c sqlx_remote.h
		replication_client.c 
)

set_target_properties(sqlitereporemote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqlitereporemote metautils metacomm
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})
	
add_library(sqliterepo SHARED
		version.c
		internals.h
		cache.c cache.h
		hash.h hash.c
		client_pool.c client_pool.h
		replication.c
		election.c election.h
		replication_dispatcher.c replication_dispatcher.h
		repository.c sqliterepo.h
		zk_manager.c zk_manager.h
		upgrade.c upgrade.h
)
set_target_properties(sqliterepo PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqliterepo metautils metacomm
		sqlitereporemote sqliteutils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES}
		-lzookeeper_mt)

#add_executable(test_cache test_cache.c)
#target_link_libraries(test_cache sqliterepo metautils metacomm
#		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(test_repository test_repository.c)
target_link_libraries(test_repository sqliterepo sqlitereporemote
		metautils metacomm
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(test_sqliterepo test_sqliterepo.c)
target_link_libraries(test_sqliterepo sqliterepo sqlitereporemote
		metautils metacomm
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_executable(gs_m1hash hash.h gs_m1hash.c)
target_link_libraries(gs_m1hash
		metautils metacomm sqliterepo
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

install(TARGETS sqliterepo sqliteutils sqlitereporemote
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

