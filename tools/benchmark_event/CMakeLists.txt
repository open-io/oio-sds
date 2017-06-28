add_definitions(-DG_LOG_DOMAIN="oio.tools.bench")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . ../..
		${CMAKE_CURRENT_BINARY_DIR})

add_executable(
	bench_event_agent
	bench_event_agent.c
    ../../proxy/path_parser.c ../../proxy/path_parser.h
    ../../proxy/transport_http.c ../../proxy/transport_http.h
    ../../rawx-apache2/src/rawx_event.c ../../rawx-apache2/src/rawx_event.h
    fake_service.c fake_service.h
    send_events.c fake_service.h
)

target_link_libraries(bench_event_agent
		oioevents
		server gridcluster
		metautils
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES} ${CURL_LIBRARIES})
