#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_library(meta2remote SHARED
		meta2_remote.c
		meta2_remote.h)
set_target_properties(meta2remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta2remote
		metautils
		${GLIB2_LIBRARIES})

install(FILES
			meta2_remote.h
		DESTINATION include/meta2/remote
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS meta2remote
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

