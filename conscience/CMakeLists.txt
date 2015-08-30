add_definitions(-DG_LOG_DOMAIN="oio.conscience")

include_directories(BEFORE . .. ../..)

include_directories(AFTER ${GLIB2_INCLUDE_DIRS}
		${LUA_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS})

link_directories(${GLIB2_LIBRARY_DIRS}
		${LUA_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS}
		${CURL_INCLUDE_DIRS})

add_library(gridcluster-conscience STATIC srvset.c)
target_link_libraries(gridcluster-conscience
		metautils ${GLIB2_LIBRARIES})

add_library(gridcluster-remote SHARED remote.c)
set_target_properties(gridcluster-remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(gridcluster-remote
		metautils oiocore oiosds ${GLIB2_LIBRARIES} ${CURL_LIBRARIES} ${JSONC_LIBRARIES})

add_library(gridcluster-lb SHARED lb.c)
set_target_properties(gridcluster-lb PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(gridcluster-lb
		metautils gridcluster-remote
		${GLIB2_LIBRARIES})

add_executable(gridcluster-server server.c)
bin_prefix(gridcluster-server -cluster-server)
target_link_libraries(gridcluster-server
		metautils server gridcluster-conscience
		${GLIB2_LIBRARIES} ${LUA_LIBRARIES})

add_executable(gridcluster-client client.c)
set_target_properties(gridcluster-client PROPERTIES OUTPUT_NAME gridcluster)
bin_prefix(gridcluster-client -cluster)
target_link_libraries(gridcluster-client
		gridcluster-remote
		metautils ${GLIB2_LIBRARIES})

add_executable (gridcluster-conscience-test test_srvset.c)
target_link_libraries (gridcluster-conscience-test gridcluster-conscience)

install(TARGETS
			gridcluster-lb
			gridcluster-remote
			gridcluster-server
			gridcluster-client
        LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

