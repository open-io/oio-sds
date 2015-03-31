
add_definitions(-DHAVE_UGLY_RC_FUNCTIONS=1)

include_directories(BEFORE
		..
		${CMAKE_CURRENT_BINARY_DIR}/..)

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_executable(metacd_http metacd_http.c path_parser.c transport_http.c)
bin_prefix(metacd_http -proxy)

target_link_libraries(metacd_http
		metautils server hcresolve
		gridcluster gridcluster-remote
		meta2v2remote meta2v2utils
		meta1remote sqlitereporemote
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES})

install(TARGETS metacd_http 
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

