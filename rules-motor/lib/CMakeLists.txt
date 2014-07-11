include_directories(BEFORE . ../..
		../../client/c/lib)

include_directories(AFTER
		${PYTHON_INCLUDE_PATH}
		${LZO_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ATTR_INCLUDE_DIRS})

link_directories(
		${LZO_LIBRARY_DIRS}
		${ZLIB_LIBRARY_DIRS}
		${ATTR_LIBRARY_DIRS})

add_library(rulesmotorc2py SHARED c2python.c motor.h)

set_target_properties(rulesmotorc2py PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rulesmotorc2py 
		metautils gridcluster rawx meta2mover
		-lm -ldl -lpthread -lutil ${PYTHON_LIBRARIES} ${GLIB2_LIBRARIES})

add_library(rulesmotorpy2c SHARED python2c.c motor.h)

set_target_properties(rulesmotorpy2c PROPERTIES SOVERSION ${ABI_VERSION})

target_link_libraries(rulesmotorpy2c
		metautils gridcluster rawx meta2mover integrity
		-lm -ldl -lpthread -lutil ${PYTHON_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS rulesmotorc2py rulesmotorpy2c
		LIBRARY DESTINATION ${LD_LIBDIR})

