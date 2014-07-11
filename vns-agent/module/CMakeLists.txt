set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

include_directories(BEFORE . ../.. ..)

add_library(msg_vns_agent MODULE msg_vns_agent.c)

set_target_properties(msg_vns_agent PROPERTIES PREFIX "" SUFFIX .so)

target_link_libraries(msg_vns_agent
		metautils metacomm meta1remote gridcluster vns_agent
		${GLIB2_LIBRARIES})

install(TARGETS msg_vns_agent
		LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY})

