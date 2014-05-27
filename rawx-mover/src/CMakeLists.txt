set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

add_definitions(-DHAVE_COMPRESSION)

include_directories(BEFORE . ../..
		../../client/c/lib
		${CMAKE_CURRENT_BINARY_DIR}/../..)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS})

link_directories(
		${SQLITE3_LIBRARY_DIRS})

add_executable(gs-rawx-mover main.c lock.c lock.h)
bin_prefix(gs-rawx-mover -rawx-mover)
target_link_libraries(gs-rawx-mover
	metautils gridclient meta2v2remote rawx hcresolve
	gridcluster-remote gridcluster-events gridcluster integrity
	${NEON_LIBRARIES} ${GLIB2_LIBRARIES} -lattr -lm -lcrypto)

install(TARGETS gs-rawx-mover
		RUNTIME DESTINATION bin)

