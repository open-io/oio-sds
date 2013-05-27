add_definitions(-DHAVE_COMPRESSION)

include_directories(BEFORE .
		../../metautils/lib
		../../cluster/lib ../../cluster/agent ../../cluster/events
		../../meta0/remote
		../../meta1/remote
		../../meta2/remote
		../../rawx-lib/src
		../../client/c/lib)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS})

link_directories(
		${SQLITE3_LIBRARY_DIRS})

add_executable(redc-rawx-mover main.c lock.c lock.h)

target_link_libraries(redc-rawx-mover
	metautils gridclient meta2remote rawx
	gridcluster-remote gridcluster-events gridcluster
	${NEON_LIBRARIES} ${GLIB2_LIBRARIES} -lattr -lm -lcrypto)

add_executable(redc-chunk-mover core.c utils.c chunk_mover.c mover.h lock.c lock.h)

target_link_libraries(redc-chunk-mover
	metautils gridclient meta2remote rawx
	gridcluster-remote gridcluster-events gridcluster
	${NEON_LIBRARIES} ${GLIB2_LIBRARIES} -lattr -lm -lcrypto)

install(TARGETS redc-rawx-mover redc-chunk-mover
		RUNTIME DESTINATION bin)

