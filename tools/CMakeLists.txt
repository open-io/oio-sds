
include_directories(BEFORE ../client/c/lib)

add_executable(tool-grep oio-grep.c)
bin_prefix(tool-grep "-grep")
target_link_libraries(tool-grep gridclient)

add_executable(tool-roundtrip oio-roundtrip.c)
bin_prefix(tool-roundtrip "-roundtrip")
target_link_libraries(tool-roundtrip gridclient)

add_executable(tool-roundtrip2 oio-roundtrip2.c)
bin_prefix(tool-roundtrip2 "-roundtrip2")
target_link_libraries(tool-roundtrip2 gridclient)


install(TARGETS tool-grep tool-roundtrip tool-roundtrip2
		RUNTIME DESTINATION bin)


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

