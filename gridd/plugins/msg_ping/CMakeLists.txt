#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../.. ../../..)

add_library(msg_ping MODULE msg_ping.c)
set_target_properties(msg_ping PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(msg_ping metautils metacomm ${GLIB2_LIBRARIES})

install(TARGETS msg_ping
        LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY}
        RUNTIME DESTINATION bin)

