#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../.. ../../..)

add_library(msg_stats MODULE msg_stats.c msg_stats.h)
set_target_properties(msg_stats PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(msg_stats metautils metacomm ${GLIB2_LIBRARIES})

install(TARGETS msg_stats
        LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY}
        RUNTIME DESTINATION bin)

