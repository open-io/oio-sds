include_directories(BEFORE .
		../../..
		../../../metautils/lib)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metacd.conf.in
		${CMAKE_CURRENT_BINARY_DIR}/metacd.conf @ONLY)

add_library(metacd_module MODULE
		limited_cache.c limited_cache.h
		locktab.c locktab.h
		metacd_module.c metacd_module.h)
set_target_properties(metacd_module PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(metacd_module
		metautils metacomm meta2remote meta0remote meta1remote
		gridcluster gridclient
		${GLIB2_LIBRARIES})

install(TARGETS metacd_module
		LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY})

