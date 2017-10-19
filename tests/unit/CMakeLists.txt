add_definitions(-DG_LOG_DOMAIN="oio.tests.unit")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
		${CMAKE_SOURCE_DIR}
		${CMAKE_BINARY_DIR}
		${CMAKE_BINARY_DIR}/metautils/lib
		${CMAKE_BINARY_DIR}/metautils/asn1c)

include_directories(ATER
		${ZK_INCLUDE_DIRS}
		${SQLITE3_INCLUDE_DIRS})

link_directories(
		${ZK_LIBRARY_DIRS}
		${SQLITE3_LIBRARY_DIRS})

set(COMMON oiocore oiosds metautils ${GLIB2_LIBRARIES})

add_executable(test_lb test_lb.c)
target_link_libraries(test_lb metautils ${COMMON})
add_test(NAME core/lb COMMAND test_lb)

add_executable(test_asn1_message test_asn1_message.c)
target_link_libraries(test_asn1_message ${COMMON})
add_test(NAME core/asn1_message COMMAND test_asn1_message)

add_executable(test_oio_ext test_ext.c)
target_link_libraries(test_oio_ext ${COMMON})
add_test(NAME core/ext COMMAND test_oio_ext)

add_executable(test_oio_url test_url.c)
target_link_libraries(test_oio_url ${COMMON})
add_test(NAME core/url COMMAND test_oio_url)

add_executable(test_variable_period test_variable_period.c)
target_link_libraries(test_variable_period ${COMMON})
add_test(NAME core/variable_period COMMAND test_variable_period)

add_executable(test_core_sysstat test_core_sysstat.c)
target_link_libraries(test_core_sysstat ${COMMON})
add_test(NAME core/sysstat COMMAND test_core_sysstat)

add_executable(test_cache_lru test_cache_lru.c)
target_link_libraries(test_cache_lru oiocache)
add_test(NAME cache/lru COMMAND test_cache_lru)

add_executable(test_nsinfo test_nsinfo.c)
target_link_libraries(test_nsinfo metautils ${COMMON})
add_test(NAME metautils/nsinfo COMMAND test_nsinfo)

add_executable(test_stg_policy test_stg_policy.c)
target_link_libraries(test_stg_policy ${COMMON})
add_test(NAME metautils/stgpol COMMAND test_stg_policy)

add_executable(test_svc_policy test_svc_policy.c)
target_link_libraries(test_svc_policy ${COMMON})
add_test(NAME metautils/svc_policy COMMAND test_svc_policy)

add_executable(test_logger test_logger.c)
target_link_libraries(test_logger ${COMMON})
add_test(NAME metautils/logger COMMAND test_logger)

add_executable(test_addr test_addr.c)
target_link_libraries(test_addr ${COMMON})
add_test(NAME metautils/addr COMMAND test_addr)

add_executable(test_gridd_client test_gridd_client.c)
target_link_libraries(test_gridd_client ${COMMON})
add_test(NAME metautils/gridd_client COMMAND test_gridd_client)

add_executable(test_lrutree test_lrutree.c)
target_link_libraries(test_lrutree ${COMMON})
add_test(NAME metautils/lru COMMAND test_lrutree)

add_executable(test_str test_str.c)
target_link_libraries(test_str ${COMMON})
add_test(NAME metautils/str COMMAND test_str)

add_executable(test_gba test_gba.c)
target_link_libraries(test_gba ${COMMON})
add_test(NAME metautils/gba COMMAND test_gba)

add_executable(test_meta2_backend test_meta2_backend.c)
target_link_libraries(test_meta2_backend meta2v2 ${COMMON})
add_test(NAME meta2/backend COMMAND test_meta2_backend)

add_executable(test_meta1_backend test_meta1_backend.c)
target_link_libraries(test_meta1_backend meta1v2 oioevents ${COMMON})
add_test(NAME meta1/backend COMMAND test_meta1_backend)

add_executable(test_stats_holder test_stats_holder.c)
target_link_libraries(test_stats_holder server ${COMMON})
add_test(NAME server/stats COMMAND test_stats_holder)

add_executable(test_sqliterepo_version test_sqliterepo_version.c)
target_link_libraries(test_sqliterepo_version sqliterepo ${COMMON})
add_test(NAME sqliterepo/version COMMAND test_sqliterepo_version)

add_executable(test_sqliterepo_election test_sqliterepo_election.c)
target_link_libraries(test_sqliterepo_election sqliterepo ${COMMON})
add_test(NAME sqliterepo/election COMMAND test_sqliterepo_election)

add_executable(test_sqliterepo_cache test_sqliterepo_cache.c)
target_link_libraries(test_sqliterepo_cache sqliterepo sqlitereporemote ${COMMON})
add_test(NAME sqliterepo/cache COMMAND test_sqliterepo_cache)

add_executable(test_sqliterepo_repo test_sqliterepo_repo.c)
target_link_libraries(test_sqliterepo_repo sqliterepo sqlitereporemote ${COMMON})
add_test(NAME sqliterepo/repository COMMAND test_sqliterepo_repo)

add_executable(test_sqlx_client_mem test_sqlx_client.c)
target_link_libraries(test_sqlx_client_mem oiosqlx oiosqlx_local ${COMMON})
add_test(NAME sqlx/client/mem COMMAND test_sqlx_client_mem)

add_executable(test_events_queue test_events_queue.c)
target_link_libraries(test_events_queue sqlxsrv oioevents ${COMMON})
add_test(NAME events/abstract COMMAND test_events_queue)

add_executable(test_events_beanstalkd test_events_beanstalkd.c)
target_link_libraries(test_events_beanstalkd ${COMMON} oioevents server)
add_test(NAME events/beanstalkd COMMAND test_events_beanstalkd)

