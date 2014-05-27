#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_library(gridcluster-conscience SHARED
	conscience_broken_holder.h
	conscience.c conscience.h
	conscience_broken_holder_common.h
	conscience_srv.h
	conscience_srvtype.h

	conscience_broken_holder.c
	conscience_broken_holder_add.c
	conscience_broken_holder_remove.c
	conscience_broken_holder_fix.c
	conscience_srv.c
	conscience_srvtype.c)

set_target_properties(gridcluster-conscience PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(gridcluster-conscience
		metautils metacomm 
		gridcluster gridcluster-events gridcluster-remote
		-lm ${GLIB2_LIBRARIES})

install(FILES
			conscience.h
			conscience_srv.h
			conscience_srvtype.h
			conscience_broken_holder.h
			conscience_broken_holder_common.h
		DESTINATION include/cluster/conscience
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS gridcluster-conscience
        LIBRARY DESTINATION ${LD_LIBDIR}
        RUNTIME DESTINATION bin)

