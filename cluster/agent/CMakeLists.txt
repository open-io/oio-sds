#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE . .. ../..)

add_executable(gridagent 
	accept_worker.c accept_worker.h
	agent.c agent.h
	asn1_request_worker.c asn1_request_worker.h
	broken_task_get.c
	broken_task_push.c
	broken_worker_clear.c
	broken_worker_fetch.c
	broken_worker_fix.c
	broken_worker_store.c
	broken_workers.h
	cluster_conf_parser.c
	cluster_conf_parser.h
	config.c config.h
	cpu_stat_task_worker.c cpu_stat_task_worker.h
	event_common.c
	event_forwarder_worker.c
	event_receiver_worker.c
	event_task_configure.c
	event_workers.h
	fs.c fs.h
	get_ns_worker.c get_ns_worker.h
	gridagent.conf
	gridagent.h
	http_request_worker.c http_request_worker.h
	io_scheduler.c io_scheduler.h
	io_stat_task_worker.c io_stat_task_worker.h
	main_events.c
	main_reqagent.c
	main_supervisor.c
	message.c message.h
	namespace_get_task_worker.c namespace_get_task_worker.h
	read_message_worker.c read_message_worker.h
	request_worker.c request_worker.h
	server.c server.h
	services_task_check.c services_task_get_services.c services_task_get_types.c services_task_push.c
	services_worker_clear.c services_worker_get_one.c services_worker_list.c services_worker_push.c services_workers.h
	task.h
	task_scheduler.c task_scheduler.h
	worker.h
	write_message_worker.c write_message_worker.h)

bin_prefix_full(gridagent -cluster-agent)

target_link_libraries(gridagent
	gridcluster gridcluster-events gridcluster-eventsremote gridcluster-remote gridcluster-conscience
	metautils metacomm
	-lm ${GLIB2_LIBRARIES})

install(FILES
			agent.h
			gridagent.h
			task.h
		DESTINATION include/cluster/agent
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS gridagent
        LIBRARY DESTINATION ${LD_LIBDIR}
        RUNTIME DESTINATION bin)

