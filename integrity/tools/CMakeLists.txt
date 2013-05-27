include_directories(BEFORE .
		../../metautils/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events
		../../meta2/remote
		../../client/c/lib
		../../rawx-lib/src
		../../rules-motor/lib
		../lib)

include_directories(AFTER
		${PYTHON_INCLUDE_PATH}
		${DB_INCLUDE_DIRS}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_executable(redc-rebuild gs_rebuild.c repair.c repair.h)
target_link_libraries(redc-rebuild
		metautils rawx rawxclient meta2remote gridclient gridcluster
		gridcluster-events gridcluster-remote integrity
		${GLIB2_LIBRARIES})

add_executable(redc-rawx-list gs_rawx_list.c)
target_link_libraries(redc-rawx-list
		metautils rawx integrity rawxclient gridcluster gridcluster-events
		gridcluster-remote
		${GLIB2_LIBRARIES})

add_executable(redc-policycheck hc_policycheck.c)
target_link_libraries(redc-policycheck
		metautils rawx integrity rawxclient gridcluster gridcluster-events
		gridcluster-remote
		${GLIB2_LIBRARIES})

add_executable(redc-break gs_break.c)
target_link_libraries(redc-break
		metautils rawx rawxclient meta2remote gridclient gridcluster
		gridcluster-events gridcluster-remote
		${GLIB2_LIBRARIES})

add_executable(redc-path2container gs_path2container.c)
target_link_libraries(redc-path2container
		metautils gridcluster gridcluster-events gridcluster-remote
		${GLIB2_LIBRARIES})

add_executable(redc-chunk-crawler gs_chunk_crawler.c lock.c lock.h)
target_link_libraries(redc-chunk-crawler
		metautils rawx rawxclient meta2remote gridclient gridcluster
		integrity gridcluster gridcluster-events gridcluster-remote
		rulesmotorc2py rulesmotorpy2c
		${GLIB2_LIBRARIES})

add_executable(redc-meta2-crawler gs_meta2_crawler.c lock.c lock.h)
target_link_libraries(redc-meta2-crawler
		integrity metautils rawx meta2remote rulesmotorc2py
		${GLIB2_LIBRARIES})

install(TARGETS
		redc-rebuild redc-rawx-list redc-break redc-path2container
		redc-chunk-crawler redc-policycheck
		redc-meta2-crawler
		RUNTIME DESTINATION bin)

