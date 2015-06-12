
set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
set(DEPS        ${SETUP_PY_IN}
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/config.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/account/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/account/backend.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/account/server.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/common/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/common/daemon.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/common/http.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/common/utils.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/conscience/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/conscience/client.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/sds/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/sds/admin-flask.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/sds/event/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/oio/sds/event/agent.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/account/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/account/test_backend.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/account/test_server.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/account/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/common/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/common/test_utils.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/sds/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/sds/event/__init__.py"
                 "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/sds/event/test_agent.py")


set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/.timestamp")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in
                ${CMAKE_CURRENT_BINARY_DIR}/setup.py
                @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bin/account-server
                ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-server
                @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bin/event-agent
                ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-event-agent
                @ONLY)

add_custom_command(OUTPUT ${OUTPUT}
                                   COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
                                   COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
                                   DEPENDS ${DEPS})

add_custom_target(account ALL DEPENDS ${OUTPUT})

install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --prefix=${CMAKE_INSTALL_PREFIX})")


install(PROGRAMS
                    ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-account-server
                    ${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-event-agent
                DESTINATION bin)