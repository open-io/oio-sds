add_definitions(-DG_LOG_DOMAIN="oio.tools.benchmark")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_executable(
	event_benchmark
	event_benchmark.c event_benchmark.h
	../../proxy/path_parser.c ../../proxy/path_parser.h
	../../proxy/transport_http.c ../../proxy/transport_http.h
	fake_service.c fake_service.h
	event_worker.c event_worker.h
	event_sender.c event_sender.h
)

bin_prefix(event_benchmark -event-benchmark)

target_link_libraries(event_benchmark
		oioevents
		server gridcluster
		metautils
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES} ${CURL_LIBRARIES})
