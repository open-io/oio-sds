#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..
	${CMAKE_CURRENT_BINARY_DIR})

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


add_library(transp_layer SHARED
		transp_layer.h
		transp_layer.c
		transp_layer_cmd.h
		transp_layer_cmd.c)
target_link_libraries(transp_layer
		${GLIB2_LIBRARIES}
		${DBUS_LIBRARIES})


add_library(crawler_tools STATIC
        crawler_tools.h
        crawler_tools.c
        dir_explorer.c
        dir_explorer.h
        crawler_constants.h
        )
target_link_libraries(crawler_tools
        ${GLIB2_LIBRARIES})


add_library(crawler_common STATIC
        crawler_common.h
        crawler_common.c
		crawler_constants.h
		crawler-glue.h
		)
target_link_libraries(crawler_common
        transp_layer
        ${GLIB2_LIBRARIES})


add_library(action_common STATIC
		action_common.h
		action_common.c
		crawler_constants.h
		action-glue.h
		)
target_link_libraries(action_common 
		transp_layer
		${GLIB2_LIBRARIES})

add_library(trip_common STATIC
		trip_common.h
		trip_common.c
		)
target_link_libraries(trip_common
		sqliterepo
		${GLIB2_LIBRARIES})


add_executable(test_dir_explorer
		test_dir_explorer.c)
target_link_libraries(test_dir_explorer
		crawler_tools
		metautils
		${GLIB2_LIBRARIES})

install(TARGETS transp_layer
		#crawler
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION include)

add_test(NAME crawler/dir_explorer COMMAND test_dir_explorer)

