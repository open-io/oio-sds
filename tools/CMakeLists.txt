
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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/account-agent.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-agent.py
		@ONLY)

add_custom_command(OUTPUT ${OUTPUT}
				   COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
				   DEPENDS ${DEPS})

add_custom_target(tools ALL DEPENDS ${OUTPUT})

install(PROGRAMS
			zk-bootstrap.py
			zk-reset.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-proxy-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-redis-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rawx-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-rainx-monitor.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-agent.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-monitor.py
		DESTINATION bin)

