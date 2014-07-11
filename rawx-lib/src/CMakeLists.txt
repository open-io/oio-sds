include_directories(BEFORE . ../..)

include_directories(AFTER
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_library(rawx SHARED
		rawx.h
		attr_handler.c
		compression.c compression.h
		lzo_compress.c
		zlib_compress.c)

set_target_properties(rawx PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rawx
		metautils metacomm gridcluster gridcluster-events gridcluster-remote
		${NEON_LIBRARIES} -lattr -lz -llzo2)

install(FILES
			compression.h
			rawx.h
		DESTINATION include/rawx-lib/src
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS rawx
		LIBRARY DESTINATION ${LD_LIBDIR})

