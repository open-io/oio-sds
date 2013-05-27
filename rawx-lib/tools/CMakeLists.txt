include_directories(BEFORE .
		../../metautils/lib
		../src)

include_directories(AFTER
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

set(REQLIBS
		${GLIB2_LIBRARIES} metautils rawx)

add_executable(redc-compress gs_compress.c)
target_link_libraries(redc-compress ${REQLIBS})

add_executable(redc-uncompress gs_uncompress.c)
target_link_libraries(redc-uncompress ${REQLIBS})

install(TARGETS 
		redc-compress redc-uncompress
		RUNTIME DESTINATION bin)

