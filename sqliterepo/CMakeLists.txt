add_definitions(-DG_LOG_DOMAIN="oio.sqlite" -DTHREADED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_SOURCE_DIR}
		${CMAKE_BINARY_DIR}
		${CMAKE_BINARY_DIR}/metautils/asn1c
		${CMAKE_BINARY_DIR}/metautils/lib
		${CMAKE_CURRENT_BINARY_DIR})

include_directories(AFTER
		${ZK_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_remote_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_remote_variables.h
	DEPENDS
		${CMAKE_SOURCE_DIR}/confgen.py
		${CMAKE_SOURCE_DIR}/conf.json
	PRE_BUILD
	COMMENT
		"Generating the central configuration (sqliterepo_remote)"
	COMMAND
		${PYTHON_EXECUTABLE}
	ARGS
		${CMAKE_SOURCE_DIR}/confgen.py
		"sqliterepo_remote"
		${CMAKE_SOURCE_DIR}/conf.json)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_variables.h
	DEPENDS
		${CMAKE_SOURCE_DIR}/confgen.py
		${CMAKE_SOURCE_DIR}/conf.json
	PRE_BUILD
	COMMENT
		"Generating the central configuration"
	COMMAND
		${PYTHON_EXECUTABLE}
	ARGS
		${CMAKE_SOURCE_DIR}/confgen.py
		"sqliterepo"
		${CMAKE_SOURCE_DIR}/conf.json)


add_library(sqliteutils SHARED rc.c sqlite_utils.c)

set_target_properties(sqliteutils PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqliteutils metautils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(sqlitereporemote SHARED
		sqlx_remote.c
		sqlx_remote_ex.c
		replication_client.c
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_remote_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_remote_variables.h)

set_target_properties(sqlitereporemote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqlitereporemote metautils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES})

add_library(sqliterepo SHARED
		gridd_client_pool.c
		synchro.c
		version.c
		cache.c
		hash.c
		replication.c
		election.c
		replication_dispatcher.c
		repository.c
		restoration.c
		upgrade.c
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/sqliterepo_variables.h)

set_target_properties(sqliterepo PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(sqliterepo metautils
		sqlitereporemote sqliteutils
		${GLIB2_LIBRARIES} ${SQLITE3_LIBRARIES} ${ZK_LIBRARIES})

install(TARGETS sqliterepo sqliteutils sqlitereporemote
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

