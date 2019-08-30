add_definitions(-DG_LOG_DOMAIN="oio.tools.benchmark")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_executable(
	event_benchmark
	event_benchmark.c
	../../proxy/path_parser.c
	../../proxy/transport_http.c
	fake_service.c
	event_worker.c
	event_sender.c)

bin_prefix(event_benchmark -event-benchmark)
target_link_libraries(event_benchmark
		oioevents
		server gridcluster
		metautils
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES} ${CURL_LIBRARIES})

install(TARGETS
			event_benchmark
		DESTINATION bin
		CONFIGURATIONS Debug COMPONENT dev)
