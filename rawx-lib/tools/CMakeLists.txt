include_directories(BEFORE . .. ../..)

include_directories(AFTER
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

set(REQLIBS
		${GLIB2_LIBRARIES} metautils rawx)

add_executable(gs_compress gs_compress.c)
bin_prefix(gs_compress -rawx-compress)
target_link_libraries(gs_compress ${REQLIBS})

add_executable(gs_uncompress gs_uncompress.c)
bin_prefix(gs_uncompress -rawx-uncompress)
target_link_libraries(gs_uncompress ${REQLIBS})

install(TARGETS 
		gs_compress gs_uncompress
		RUNTIME DESTINATION bin)

