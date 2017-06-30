#ifndef OIO_SDS__tools__benchmark_event__bench_conf_h
#define OIO_SDS__tools__benchmark_event__bench_conf_h

#define NAME_SPACE "OPENIO"
#define RAWX_ADDRESS "127.0.0.1:4444"
#define FAKE_SERVICE_ADDRESS "127.0.0.1:4445"

enum event_type_e {
	CHUNK_NEW,
	CHUNK_DELETED,
	CONTAINER_NEW,
	CONTAINER_STATE,
	CONTAINER_DELETED,
	CONTENT_DELETED,
};

#endif /* OIO_SDS__tools__benchmark_event__bench_conf_h */
