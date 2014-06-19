#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

include_directories(AFTER
	${GLIB2_INCLUDE_DIRS}
	${DBUS_INCLUDE_DIRS}
	${PYTHON_INCLUDE_PATH}
	${LZO_INCLUDE_DIRS}
	${NEON_INCLUDE_DIRS}
	${ZK_INCLUDE_DIRS})

link_directories(
	${GLIB2_LIBRARY_DIRS}
	${DBUS_LIBRARY_DIRS}
	${LZO_LIBRARY_DIRS}
	${ZK_LIBRARY_DIRS})

add_library(trip_chunk SHARED
		lib/lib_trip.h
		lib/crawler_tools.h
		trip_chunk.c)
target_link_libraries(trip_chunk
		crawler_tools)

add_library(trip_container SHARED
		lib/lib_trip.h
		lib/crawler_tools.h
		trip_container.c)
target_link_libraries(trip_container
		crawler_tools)

add_library(trip_content SHARED
		lib/lib_trip.h
		lib/crawler_tools.h
		trip_content.c)
target_link_libraries(trip_content
		meta2remote
		crawler_tools)


add_library(trip_prefix SHARED
		lib/lib_trip.h
		lib/crawler_tools.h
		trip_prefix.c)
target_link_libraries(trip_prefix 
		sqliterepo
		trip_common
		crawler_tools)

add_library(trip_sqlx SHARED
        lib/lib_trip.h
        lib/crawler_tools.h
        trip_sqlx.c)
target_link_libraries(trip_sqlx
		#sqliterepo
		trip_common
        crawler_tools)


add_executable(crawler
		lib/crawler_common.h
		lib/crawler_tools.h
		crawler.c)
bin_prefix(crawler -crawler)
target_link_libraries(crawler
		metautils
		listenerremote
		transp_layer
		crawler_common
		crawler_tools
		#trip_chunk
		#trip_container
		#trip_content
		${GLIB2_LIBRARIES})

add_executable(crawler_cmd
		lib/crawler_common.h
		crawler_cmd.c)
bin_prefix(crawler_cmd -crawler-cmd)
target_link_libraries(crawler_cmd
		metautils
		transp_layer
		crawler_common
		crawler_tools
		${GLIB2_LIBRARIES})



add_executable(test_crawler
        test/test_crawler.c
		test/srvstub.c
        test/srvstub.h
		test/binredir.c
		test/binredir.h)
target_link_libraries(test_crawler
        crawler_tools
        metautils
		server
		meta2v2utils
        ${GLIB2_LIBRARIES})

add_executable(action_rules_motor_service
		lib/crawler_tools.h
		action_rules_motor_service.c)
target_link_libraries(action_rules_motor_service
		meta2remote
		metautils
		rulesmotorc2py
		action_common
		transp_layer
		crawler_tools
		integrity
		${GLIB2_LIBRARIES}
		${DBUS_LIBRARIES}
		${PYTHON_LIBRARIES}
		${ZMQ_LIBRARIES})

add_executable(action_integrity_service
		lib/crawler_tools.h
		action_integrity_service.c)
target_link_libraries(action_integrity_service
		metautils
		rulesmotorc2py
		action_common
		transp_layer
		crawler_tools
		integrity
		rawx
		${GLIB2_LIBRARIES}
		${DBUS_LIBRARIES}
		${SQLITE3_LIBRARIES}
		${ZMQ_LIBRARIES})

add_executable(action_purge_container_service
		lib/crawler_tools.h		
		action_purge_container_service.c)
target_link_libraries(action_purge_container_service
		meta2v2remote
		metautils
		meta2v2utils
		action_common
		transp_layer
		crawler_tools
		gridpolix
		${GLIB2_LIBRARIES}
		${DBUS_LIBRARIES}
		${NEON_LIBRARIES}
		${ZMQ_LIBRARIES})

add_executable(action_list_container_service
		lib/crawler_tools.h
		action_list_container_service.c)
target_link_libraries(action_list_container_service
		meta1remote
		metautils
		listenerremote
		gridclient
		action_common
		transp_layer
		crawler_tools
		${GLIB2_LIBRARIES}
		${DBUS_LIBRARIES}
		${NEON_LIBRARIES}
		${ZMQ_LIBRARIES})


add_executable(action_dedup_container_service
		lib/crawler_tools.h
		action_dedup_container_service.c)
target_link_libraries(action_dedup_container_service
		meta2v2remote
		metautils
		action_common
		transp_layer
		crawler_tools
		${GLIB2_LIBRARIES}
		)

install(TARGETS crawler
#		trip_test
		trip_chunk
		trip_container
		trip_content	
		trip_prefix
		trip_sqlx
#		trip_test_action
		crawler
#		action_test_trip
#		action_test_service
#		action_move_chunk_basic_service
		action_rules_motor_service
		action_purge_container_service
		action_dedup_container_service
		action_list_container_service
		action_integrity_service
		crawler_cmd
		LIBRARY DESTINATION ${LD_LIBDIR}/grid
		RUNTIME DESTINATION bin)

add_test(NAME crawler/trip_container COMMAND test_trip trip_container "/DATA/$ns/$hn/meta2-1")
add_test(NAME crawler/trip_content   COMMAND test_trip trip_container "/DATA/$ns/$hn/meta2-1")
add_test(NAME crawler/trip_chunk     COMMAND test_trip trip_chunk     "/DATA/$ns/$hn/meta2-1")
add_test(NAME crawler/trip_prefix    COMMAND test_trip trip_prefix    "/DATA/$ns/$hn/meta1-1")
add_test(NAME crawler/trip_sqlx      COMMAND test_trip trip_sqlx      "/DATA/$ns/$hn/sqlx-1")
add_test(NAME crawler/action_purge   COMMAND test_action action_purge_container_service "127.0.0.1:6005")


