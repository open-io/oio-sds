add_definitions(-DG_LOG_DOMAIN="oio.cluster.module")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER ${ZMQ_INCLUDE_DIRS})

link_directories(${ZMQ_LIBRARY_DIRS})


add_custom_command(
	OUTPUT expr.yacc.c expr.yacc.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/expr.yacc.y
	COMMAND ${BISON_EXECUTABLE}
	ARGS -d -y -o expr.yacc.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.yacc.y
)

add_custom_command(
	OUTPUT expr.lex.c
	DEPENDS expr.yacc.c expr.yacc.h
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -s -oexpr.lex.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.lex.l
)


add_executable(conscience
	server.c
	expr.clean.c expr.eval.c expr.lex.c expr.yacc.c expr.yacc.h expr.h)

target_link_libraries(conscience
	server
	${GLIB2_LIBRARIES} ${ZMQ_LIBRARIES})

bin_prefix(conscience -daemon)

install(TARGETS conscience
		LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY}
		RUNTIME DESTINATION bin)

