include_directories(BEFORE . ../..)

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS}
		${APACHE2_INCLUDE_DIRS}
		${APR_INCLUDE_DIRS}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS}
		${APACHE2_LIBRARY_DIRS}
		${APR_LIBRARY_DIRS})

add_library(mod_dav_rawx MODULE
		mod_dav_rawx.c
		mod_dav_rawx.h
		rawx_bucket.c
		rawx_bucket.h
		rawx_config.h
		rawx_config_stats.c
		rawx_config_utils.c
		rawx_internals.c
		rawx_internals.h
		rawx_properties.c
		rawx_repo_core.h
		rawx_repo_core.c
		rawx_repository.c
		rawx_req_info.c
		rawx_chunk_update.c
		rawx_stats_rrd.c
		rawx_stats_rrd.h)

set_target_properties(mod_dav_rawx PROPERTIES PREFIX "" SUFFIX .so)

target_link_libraries(mod_dav_rawx
		metautils rawx
		${APR_LIBRARIES} ${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES}
		-lz -llzo2)

install(TARGETS mod_dav_rawx
		LIBRARY DESTINATION ${APACHE2_LIBRARY_DIRS}/modules)

