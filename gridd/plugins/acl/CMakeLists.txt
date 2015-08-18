add_definitions(-DG_LOG_DOMAIN="oio.gridd.acl")

include_directories(BEFORE . ../.. ../../..)

add_library(acl MODULE acl.c)
set_target_properties(acl PROPERTIES PREFIX "" SUFFIX .so)
target_link_libraries(acl metautils gridcluster ${GLIB2_LIBRARIES})

install(TARGETS acl 
        LIBRARY DESTINATION ${GRIDD_PLUGINS_DIRECTORY}
        RUNTIME DESTINATION bin)

