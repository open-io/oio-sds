add_definitions(-DG_LOG_DOMAIN="oio.tools")

include_directories(BEFORE ..)

add_executable(echo-server oio-echo-server.c)
bin_prefix(echo-server "-echo-server")
target_link_libraries(echo-server metautils server gridcluster ${GLIB2_LIBRARIES})

add_executable(oio-tool oio-tool.c)
bin_prefix(oio-tool -tool)
target_link_libraries(oio-tool metautils ${GLIB2_LIBRARIES})


set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/.timestamp")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sds-reset.sh
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sds-bootstrap.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
		@ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/redis-monitor.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-redis-monitor.py
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/proxy-monitor.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-proxy-monitor.py
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/rawx-monitor.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rawx-monitor.py
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/rainx-monitor.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rainx-monitor.py
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/account-monitor.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-monitor.py
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/rdir-monitor.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rdir-monitor.py
		@ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-sds.pc.in
		${CMAKE_CURRENT_BINARY_DIR}/oio-sds.pc
		@ONLY)

add_custom_command(OUTPUT ${OUTPUT}
				   COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
				   DEPENDS ${DEPS})

add_custom_target(tools ALL DEPENDS ${OUTPUT})

install(FILES
			${CMAKE_CURRENT_BINARY_DIR}/oio-sds.pc
		DESTINATION ${LD_LIBDIR}/pkgconfig
		PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS
			echo-server
			oio-tool
		DESTINATION bin)

install(PROGRAMS
			zk-bootstrap.py
			zk-reset.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-proxy-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-redis-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rawx-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rainx-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rdir-monitor.py
		DESTINATION bin)

