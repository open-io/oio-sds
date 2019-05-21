add_definitions(-DG_LOG_DOMAIN="oio.ecp")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_library(oioecp SHARED ecp.c)

set_target_properties(oioecp PROPERTIES PUBLIC_HEADER "oio_core.h" VERSION 0.0.0 SOVERSION 0)
target_link_libraries(oioecp
		${JSONC_LIBRARIES} ${GLIB2_LIBRARIES}
		${EC_LIBRARIES} ${PYTHON_LIBRARIES})


install(TARGETS oioecp
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include)

