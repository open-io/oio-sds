#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_library(vnsagentremote SHARED vns_agent_remote.c vns_agent_remote.h)

set_target_properties(vnsagentremote PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(vnsagentremote
		metautils metacomm
		${GLIB2_LIBRARIES})

install(TARGETS vnsagentremote
		LIBRARY DESTINATION ${LD_LIBDIR})

