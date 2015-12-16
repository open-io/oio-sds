add_definitions(-DG_LOG_DOMAIN="oio.rawx.tools")

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
		attr_handler.c
		compression.c
		utils_rawx_maintenance.c
		lzo_compress.c
		zlib_compress.c)

set_target_properties(rawx PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rawx
		metautils gridcluster
		${ATTR_LIBRARIES} ${ZLIB_LIBRARIES} ${LZO_LIBRARIES})

install(TARGETS rawx
		LIBRARY DESTINATION ${LD_LIBDIR})

