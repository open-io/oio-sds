add_definitions(-DG_LOG_DOMAIN="oio.rawx.tools")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../..)

include_directories(AFTER
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

link_directories(
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_library(rawx SHARED
		attr_handler.c
		compression.c
		zlib_compress.c)

set_target_properties(rawx PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rawx
		metautils gridcluster
		${ATTR_LIBRARIES} ${ZLIB_LIBRARIES})

install(TARGETS rawx
		LIBRARY DESTINATION ${LD_LIBDIR})

