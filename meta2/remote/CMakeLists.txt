#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..
		${CMAKE_CURRENT_BINARY_DIR}/../..)

add_custom_command(
	OUTPUT meta2_services_remote.h meta2_services_remote.c
	COMMAND ${PERL_EXECUTABLE}
	ARGS ${CMAKE_CURRENT_SOURCE_DIR}/../generator.pl --module=meta2_services --prefix=meta2 --tpldir=${CMAKE_CURRENT_SOURCE_DIR}/../templates --outdir=. remote
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/../generator.pl
		${CMAKE_CURRENT_SOURCE_DIR}/../templates/common.tpl
		${CMAKE_CURRENT_SOURCE_DIR}/../templates/remote.c.tpl
		${CMAKE_CURRENT_SOURCE_DIR}/../templates/remote.h.tpl
)

add_library(meta2servicesremote SHARED
		${CMAKE_CURRENT_BINARY_DIR}/meta2_services_remote.h
		${CMAKE_CURRENT_BINARY_DIR}/meta2_services_remote.c)
set_target_properties(meta2servicesremote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta2servicesremote
		metautils metacomm
		${GLIB2_LIBRARIES})

add_library(meta2remote SHARED
		utils.c dump.c restore.c meta2_remote.c meta2_remote.h)
set_target_properties(meta2remote PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(meta2remote
		metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(meta2_client client.c)
bin_prefix_full(meta2_client -meta2-client)
target_link_libraries(meta2_client
		metautils metacomm meta2remote meta2servicesremote
		${GLIB2_LIBRARIES})
add_dependencies(meta2_client meta2remote)

install(FILES
			meta2_remote.h
			${CMAKE_CURRENT_BINARY_DIR}/meta2_services_remote.h
		DESTINATION include/meta2/remote
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS meta2remote meta2servicesremote meta2_client
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

