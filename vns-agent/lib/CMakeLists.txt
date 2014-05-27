#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_library(vns_agent SHARED vns_agent.c vns_agent.h vns_agent_internals.h)

set_target_properties(vns_agent PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(vns_agent
		metautils gridcluster meta1remote
		${GLIB2_LIBRARIES})

install(TARGETS vns_agent LIBRARY DESTINATION ${LD_LIBDIR})


