include_directories(BEFORE .
        ../meta2v2
	../metautils/lib
	../meta2/remote
	../cluster/lib ../cluster/agent ../cluster/events
	../rules-motor/lib
	../rawx-lib/src
	${CMAKE_CURRENT_BINARY_DIR}/../meta2v2)

include_directories(AFTER
        ${GLIB2_INCLUDE_DIRS}
        ${DBUS_INCLUDE_DIRS}
	${PYTHON_INCLUDE_PATH}
	${LZO_INCLUDE_DIRS}
	${NEON_INCLUDE_DIRS})

link_directories(
        ${GLIB2_LIBRARY_DIRS}
        ${DBUS_LIBRARY_DIRS}
	${LZO_LIBRARY_DIRS})

add_executable(redc-crawler
                crawler_common_tools.c
                crawler_common_tools.h
                crawler.c)
target_link_libraries(redc-crawler
                metautils
                ${GLIB2_LIBRARIES}
                ${DBUS_LIBRARIES})

#add_library(trip_test SHARED
#		lib_trip.h
#		crawler_common_tools.h
#		crawler_constants.h
#		crawler_common_tools.c
#		trip_test.c)
#target_link_libraries(trip_test)

add_library(trip_chunk SHARED
		lib_trip.h
		crawler_common_tools.h
		crawler_constants.h
		crawler_common_tools.c
		trip_chunk.c)
target_link_libraries(trip_chunk)

add_library(trip_container SHARED
		lib_trip.h
		crawler_common_tools.h
		crawler_constants.h
		crawler_common_tools.c
		trip_container.c)
target_link_libraries(trip_container)

add_library(trip_content SHARED
                lib_trip.h
                crawler_common_tools.h
                crawler_constants.h
                crawler_common_tools.c
                trip_content.c)
target_link_libraries(trip_content
		meta2remote)

#add_executable(action_test_service
#		crawler_common_tools.c
#		crawler_common_tools.h
#		action_test_service.c)
#target_link_libraries(action_test_service
#                metautils
#                ${GLIB2_LIBRARIES}
#                ${DBUS_LIBRARIES})

#add_executable(action_move_chunk_basic_service
#		crawler_common_tools.c
#		crawler_common_tools.h
#		action_move_chunk_basic_service.c)
#target_link_libraries(action_move_chunk_basic_service
#                metautils
#                ${GLIB2_LIBRARIES}
#                ${DBUS_LIBRARIES})

add_executable(redc-crawler-cmd
		crawler_common_tools.c
		crawler_common_tools.h
		crawler_cmd.c)
target_link_libraries(redc-crawler-cmd
		metautils
                ${GLIB2_LIBRARIES}
                ${DBUS_LIBRARIES})

add_executable(action_rules_motor_service
                crawler_common_tools.c
                crawler_common_tools.h
                action_rules_motor_service.c)
target_link_libraries(action_rules_motor_service
                meta2remote
		metautils
		rulesmotorc2py
                ${GLIB2_LIBRARIES}
                ${DBUS_LIBRARIES}
		${PYTHON_LIBRARIES})

add_executable(action_integrity_service
                crawler_common_tools.c
                crawler_common_tools.h
                action_integrity_service.c)
target_link_libraries(action_integrity_service
                metautils
		rulesmotorc2py
                ${GLIB2_LIBRARIES}
                ${DBUS_LIBRARIES}
		${SQLITE3_LIBRARIES})

add_executable(action_purge_container_service
                crawler_common_tools.c
                crawler_common_tools.h
                action_purge_container_service.c)
target_link_libraries(action_purge_container_service
                meta2v2remote
		metautils
		meta2v2utils
                ${GLIB2_LIBRARIES}
                ${DBUS_LIBRARIES}
		${NEON_LIBRARIES})

add_executable(action_dedup_container_service
                crawler_common_tools.c
                crawler_common_tools.h
                action_dedup_container_service.c)
target_link_libraries(action_dedup_container_service
                meta2v2remote
		metautils
                ${GLIB2_LIBRARIES}
                ${DBUS_LIBRARIES})

install(TARGETS redc-crawler
#		trip_test
		trip_chunk
		trip_container
		trip_content
#		action_test_service
#		action_move_chunk_basic_service
		action_rules_motor_service
		action_purge_container_service
		action_dedup_container_service
		redc-crawler-cmd
                LIBRARY DESTINATION /usr/${LD_LIBDIR}/grid
                RUNTIME DESTINATION bin)
