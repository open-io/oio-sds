#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ..)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${APACHE2_INCLUDE_DIRS}
		${APR_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS}
		${LIBRAIN_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS}
		${APACHE2_LIBRARY_DIRS}
		${APR_LIBRARY_DIRS}
		${LIBRAIN_LIBRARY_DIRS})

add_library(mod_dav_rainx MODULE
		mod_dav_rainx.c
		mod_dav_rainx.h
		rainx_config.h
		rainx_config_stats.c
		rainx_config_utils.c
		rainx_internals.c
		rainx_internals.h
		rainx_properties.c
		rainx_repository.c
		rainx_req_info.c
		rainx_stats_rrd.c
		rainx_stats_rrd.h
		rainx_http_tools.c
		rainx_http_tools.h)

set_target_properties(mod_dav_rainx PROPERTIES PREFIX "" SUFFIX .so)

target_link_libraries(mod_dav_rainx
		metautils rawx
		${APR_LIBRARIES} ${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES}
		-lrain -lz -llzo2)

install(TARGETS mod_dav_rainx
		LIBRARY DESTINATION ${APACHE2_LIBRARY_DIRS}/modules)

