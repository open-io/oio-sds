add_definitions(-DG_LOG_DOMAIN="oio.tests.unit")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../../..
		${CMAKE_CURRENT_BINARY_DIR}/../..
		${CMAKE_CURRENT_BINARY_DIR}/../../metautils/lib
		${ZK_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

set(COMMON oiocore oiosds metautils ${GLIB2_LIBRARIES})

add_executable(test_events_beanstalkd test_events_beanstalkd.c server.c)
target_link_libraries(test_events_beanstalkd ${COMMON} oioevents)
add_test(NAME ok/test_message_ok COMMAND test_events_beanstalkd)
