add_definitions(-DG_LOG_DOMAIN="oio.cluster.conscience")

include_directories(BEFORE . .. ../..)

add_library(gridcluster-conscience SHARED
		conscience.c conscience_srv.c conscience_srvtype.c)

set_target_properties(gridcluster-conscience PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(gridcluster-conscience
		metautils gridcluster
		-lm ${GLIB2_LIBRARIES})

install(TARGETS gridcluster-conscience
        LIBRARY DESTINATION ${LD_LIBDIR}
        RUNTIME DESTINATION bin)

