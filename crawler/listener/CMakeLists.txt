#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
        ${DBUS_INCLUDE_DIRS}
		${PYTHON_INCLUDE_PATH}
		${JSONC_INCLUDE_DIRS}
		${ZMQ_INCLUDE_DIRS})

link_directories(
        ${GLIB2_LIBRARY_DIRS}
        ${DBUS_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS}
		${ZMQ_LIBRAZY_DIRS})


add_library(listenerremote SHARED
		listener_remote.h
		listener_remote.c)

target_link_libraries(listenerremote 
		${ZMQ_LIBRARIES}
		${JSONC_LIBRARIES}
		${GLIB2_LIBRARIES})


install(TARGETS listenerremote
        LIBRARY DESTINATION ${LD_LIBDIR}
		ARCHIVE DESTINATION ${LD_LIBDIR}
        RUNTIME DESTINATION bin)


