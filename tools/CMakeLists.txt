
set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
set(DEPS        ${SETUP_PY_IN} "${CMAKE_CURRENT_SOURCE_DIR}/oio/__init__.py" "${CMAKE_CURRENT_SOURCE_DIR}/oio/sds/__init__.py")
set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/.timestamp")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in
		${CMAKE_CURRENT_BINARY_DIR}/setup.py
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sds-reset.sh
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
		@ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sds-bootstrap.py
		${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
		@ONLY)

add_custom_command(OUTPUT ${OUTPUT}
				   COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
				   COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
				   DEPENDS ${DEPS})

add_custom_target(target ALL DEPENDS ${OUTPUT})

install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --prefix=${CMAKE_INSTALL_PREFIX})")

install(FILES
			zk-bootstrap.py
			zk-reset.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-bootstrap.py
			${CMAKE_CURRENT_BINARY_DIR}/${EXE_PREFIX}-reset.sh
		DESTINATION bin
		PERMISSIONS
			OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)

