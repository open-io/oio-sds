#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..
		../../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/../..)

add_executable(gs_meta2_mover
		gs_meta2_mover.c)
bin_prefix(gs_meta2_mover -meta2-mover)
target_link_libraries(gs_meta2_mover
		meta2mover metautils metacomm meta2remote meta1remote
		gridcluster meta2v2remote
		${GLIB2_LIBRARIES})

install(TARGETS gs_meta2_mover
	RUNTIME DESTINATION bin)
