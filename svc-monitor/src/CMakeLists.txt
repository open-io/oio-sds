#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../..)

include_directories(AFTER
		${GRIDINIT_INCLUDE_DIRS})

link_directories(
		${SQLITE3_LIBRARY_DIRS}
		${GRIDINIT_LIBRARY_DIRS})

add_executable(svc-monitor main.c)
bin_prefix(svc-monitor -svc-monitor)
target_link_libraries(svc-monitor
		metautils gridinit-utils gridcluster
		${GLIB2_LIBRARIES})

install(TARGETS svc-monitor RUNTIME DESTINATION bin)

