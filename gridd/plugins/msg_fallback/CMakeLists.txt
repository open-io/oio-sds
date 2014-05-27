#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../.. ../../..)

add_library(msg_fallback MODULE msg_fallback.c)
set_target_properties(msg_fallback PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(msg_fallback metautils metacomm ${GLIB2_LIBRARIES})

install(TARGETS msg_fallback
        LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY}
        RUNTIME DESTINATION bin)

