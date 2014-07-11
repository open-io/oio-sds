#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..
		../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/..
		${CMAKE_CURRENT_BINARY_DIR}/../metautils/lib)

add_library(msg_polix MODULE
		module.c
		event_storage.c)

set_target_properties(msg_polix PROPERTIES PREFIX "" SUFFIX .so)

target_link_libraries(msg_polix
		metautils gridpolix
		${GLIB2_LIBRARIES})

install(TARGETS msg_polix LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY})


add_library(gridpolix SHARED
	polix_action.c
	polix_action.h
	event_manager.c
	event_manager.h
)

set_target_properties(gridpolix PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(gridpolix
		gridclient meta2remote metautils
		${GLIB2_LIBRARIES})

install(TARGETS gridpolix LIBRARY DESTINATION ${LD_LIBDIR})

