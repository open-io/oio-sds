add_definitions(-DG_LOG_DOMAIN="oio.tools")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
	${ZK_INCLUDE_DIRS})

add_executable(oio-zk-harass oio-zk-harass.c)
bin_prefix(oio-zk-harass -zk-harass)
target_link_libraries(oio-zk-harass
	metautils sqliterepo
	${ZK_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable(oio-tool oio-tool.c)
bin_prefix(oio-tool -tool)
target_link_libraries(oio-tool
	oiocore metautils
	server hcresolve oioevents
	sqliterepo sqlitereporemote
	meta2v2utils
	${GLIB2_LIBRARIES})


set(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/.timestamp")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-unlock-all.sh
        ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-unlock-all.sh
        @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-flush-all.sh
                ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-flush-all.sh
        @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-wait-scored.sh
        ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-wait-scored.sh
        @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-reset.sh
        ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
        @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-bootstrap.py
        ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
        @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-sds.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/oio-sds.pc
        @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-test-config.py
        ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-test-config.py
        @ONLY)

add_custom_command(OUTPUT ${OUTPUT}
                   COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
                   DEPENDS ${DEPS})

add_custom_target(tools ALL DEPENDS ${OUTPUT})

install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/oio-sds.pc
        DESTINATION ${PKGCONFIG_DIRECTORY}
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS oio-tool DESTINATION bin)

install(PROGRAMS
            zk-bootstrap.py
            zk-reset.py
            oio-election-reset.py
            oio-election-smudge.py
            oio-election-stat.py
            oio-election-dump.py
            ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-unlock-all.sh
            ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-flush-all.sh
            ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-wait-scored.sh
            ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
            ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-test-config.py
            ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
        DESTINATION bin)

