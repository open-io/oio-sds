#ifndef _GRID_STORAGE_H
#define _GRID_STORAGE_H

#include <metautils/lib/metautils.h>

config_require(util_funcs)
config_add_mib(GRIDSTORAGE-MIB)

struct meta2_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char addr[STRLEN_ADDRINFO];
	int score;
	guint32 nb_thread;
	guint32 req_total;
	guint32 req_create;
	guint32 req_content_retrieve;
	guint32 req_list;
	guint32 req_close;
	guint32 req_destroy;
	guint32 req_content_remove;
	guint32 req_open;
	guint32 req_failures;
	guint32 req_content_add;
	guint32 req_content_append;
	guint32 req_content_commit;
	guint32 req_chunk_commit;
	guint32 req_rplcontent;
	guint32 req_statcontent;

	guint32 time_create;
	guint32 time_content_retrieve;
	guint32 time_list;
	guint32 time_close;
	guint32 time_destroy;
	guint32 time_content_remove;
	guint32 time_open;
	guint32 time_content_add;
	guint32 time_content_append;
	guint32 time_content_commit;
	guint32 time_chunk_commit;
	guint32 time_rplcontent;
	guint32 time_statcontent;

	guint32 req_maintenance_getcontent;
	guint32 req_maintenance_getchunks;
	guint32 req_maintenance_setcontent;
	guint32 req_maintenance_setchunks;
	guint32 req_maintenance_delcontent;
	guint32 req_maintenance_delchunks;
	guint32 req_maintenance_other;

	guint32 time_maintenance_getcontent;
	guint32 time_maintenance_getchunks;
	guint32 time_maintenance_setcontent;
	guint32 time_maintenance_setchunks;
	guint32 time_maintenance_delcontent;
	guint32 time_maintenance_delchunks;
	guint32 time_maintenance_other;

	guint32 req_prop_set_content;
	guint32 req_prop_set_container;
	guint32 req_prop_get_content;
	guint32 req_prop_get_container;
	guint32 req_prop_rm_content;
	guint32 req_prop_rm_container;
	guint32 req_prop_rpl_set_container;
	guint32 req_prop_rpl_rm_container;

	guint32 time_prop_set_content;
	guint32 time_prop_set_container;
	guint32 time_prop_get_content;
	guint32 time_prop_get_container;
	guint32 time_prop_rm_content;
	guint32 time_prop_rm_container;
	guint32 time_prop_rpl_set_container;
	guint32 time_prop_rpl_rm_container;
};

struct rawx_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char volume[LIMIT_LENGTH_VOLUMENAME];
	char addr[STRLEN_ADDRINFO];
	int score;
	int free_chunk;
	int io_idle;

	guint32 req_all;
	guint32 req_get;
	guint32 req_put;
	guint32 req_del; 
	guint32 req_info; 
	guint32 req_stat; 
	guint32 req_raw; 
	guint32 req_other; 

	guint32 rep_2xx;
	guint32 rep_4xx;
	guint32 rep_5xx;
	guint32 rep_403;
	guint32 rep_404;
	guint32 rep_other;

	guint32 bytes_read;
	guint32 bytes_written;
};

struct saver_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char addr[STRLEN_ADDRINFO];
	int score;

	guint32 req_push;
	guint32 req_status;
	guint32 workers_bytes;
	guint32 workers_ok;
	guint32 workers_ko;
};

struct tsmx_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char addr[STRLEN_ADDRINFO];
	int score;

	int idle_log;
	int idle_db;
	int idle_stg;
	guint32 req_put;
	guint32 req_get;
	guint32 req_del;
	guint32 failed;
	guint32 bytes_in;
	guint32 bytes_out;
};

struct solr_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char addr[STRLEN_ADDRINFO];
	int score;

	guint32 req_update;
	guint32 req_search;
	guint32 commits;
	guint32 time_update;
	guint32 time_search;
};

struct rplx_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char addr[STRLEN_ADDRINFO];
	int score;

	guint32 nb_thread;
	guint32 worker_current;
	guint32 worker_idle;
	guint32 worker_max;
	guint32 worker_queue;
	guint32 req_push;
	guint32 req_status;
	guint32 req_total;
	guint32 time_push;
	guint32 time_status;
	guint32 time_total;
};

struct evt_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	guint32	incoming_nb;
	guint32 incoming_age;
	guint32 incoming_oldest;
	guint32 pending_nb;
	guint32 pending_age;
	guint32 pending_oldest;
};

struct csc_snmp_data {
	char namespace[LIMIT_LENGTH_NSNAME];
	char addr[STRLEN_ADDRINFO];
	guint32 nb_thread;
	guint32 nb_rawx;
	guint32 nb_rawx_online;
};

void init_grid_storage(void);
FindVarMethod var_meta2_number;
FindVarMethod var_meta2_entry;
FindVarMethod var_rawx_number;
FindVarMethod var_rawx_entry;
FindVarMethod var_tsmx_number;
FindVarMethod var_tsmx_entry;
FindVarMethod var_saver_number;
FindVarMethod var_saver_entry;
FindVarMethod var_solr_number;
FindVarMethod var_solr_entry;
FindVarMethod var_rplx_number;
FindVarMethod var_rplx_entry;
FindVarMethod var_evt_number;
FindVarMethod var_evt_entry;
FindVarMethod var_csc_number;
FindVarMethod var_csc_entry;

#define META2_NUMBER                 0
#define META2_INDEX                  1
#define META2_NAMESPACE              2
#define META2_REQ_TOTAL              3
#define META2_REQ_CREATE             4
#define META2_REQ_ALLGETS            5
#define META2_REQ_LIST               6
#define META2_REQ_CLOSE              7
#define META2_REQ_DESTROY            8    
#define META2_REQ_CONTENT_RM         9
#define META2_REQ_OPEN               10
#define META2_REQ_FAIL               11
#define META2_REQ_CONTENT_ALLPUTS    12
#define META2_REQ_CONTENT_ADD        13
#define META2_REQ_CONTENT_APPEND     14
#define META2_REQ_CONTENT_COMMIT     15
#define META2_REQ_CHUNK_COMMIT       16
#define META2_REQ_CONTENT_GET        17
#define META2_TIME_CREATE            18
#define META2_TIME_ALLGETS           19
#define META2_TIME_LIST              20
#define META2_TIME_CLOSE             21
#define META2_TIME_DESTROY           22
#define META2_TIME_CONTENT_RM        23
#define META2_TIME_OPEN              24
#define META2_TIME_CONTENT_ALLPUTS   25
#define META2_TIME_CONTENT_ADD       26
#define META2_TIME_CONTENT_APPEND    27
#define META2_TIME_CONTENT_COMMIT    28
#define META2_TIME_CHUNK_COMMIT      29
#define META2_TIME_CONTENT_GET       30
#define META2_ADDR                   31
#define META2_NB_THREAD              32
#define META2_SCORE                  33
#define META2_REQ_RAW_GETCONTENT     34
#define META2_REQ_RAW_GETCHUNK       35
#define META2_REQ_RAW_SETCONTENT     36
#define META2_REQ_RAW_SETCHUNK       37
#define META2_REQ_RAW_DELCONTENT     38
#define META2_REQ_RAW_DELCHUNK       39
#define META2_REQ_RAW_OTHER          40
#define META2_TIME_RAW_GETCONTENT    41
#define META2_TIME_RAW_GETCHUNK      42
#define META2_TIME_RAW_SETCONTENT    43
#define META2_TIME_RAW_SETCHUNK      44
#define META2_TIME_RAW_DELCONTENT    45
#define META2_TIME_RAW_DELCHUNK      46
#define META2_TIME_RAW_OTHER         47
#define META2_REQ_RPLCONTENT	     48
#define META2_TIME_RPLCONTENT	     49
#define META2_REQ_STATCONTENT	     50
#define META2_TIME_STATCONTENT	     51
#define META2_REQ_PROP_SET_CONTENT	52
#define META2_REQ_PROP_SET_CONTAINER	53
#define META2_REQ_PROP_GET_CONTENT	54
#define META2_REQ_PROP_GET_CONTAINER	55
#define META2_REQ_PROP_RM_CONTENT	56
#define META2_REQ_PROP_RM_CONTAINER	57
#define META2_REQ_PROP_RPL_SET_CONTAINER 58
#define META2_REQ_PROP_RPL_RM_CONTAINER	59
#define META2_TIME_PROP_SET_CONTENT	60
#define META2_TIME_PROP_SET_CONTAINER	61
#define META2_TIME_PROP_GET_CONTENT	62
#define META2_TIME_PROP_GET_CONTAINER	63
#define META2_TIME_PROP_RM_CONTENT	64
#define META2_TIME_PROP_RM_CONTAINER	65
#define META2_TIME_PROP_RPL_SET_CONTAINER 66
#define META2_TIME_PROP_RPL_RM_CONTAINER 67

#define RAWX_NUMBER               0
#define RAWX_INDEX                1
#define RAWX_NAMESPACE            2
#define RAWX_VOLUME               3
#define RAWX_ADDR                 4
#define RAWX_FREE_CHUNK           5
#define RAWX_IO_IDLE              6
#define RAWX_SCORE                7
#define RAWX_REQ_ALL              8
#define RAWX_REQ_GET              9
#define RAWX_REQ_PUT              10
#define RAWX_REQ_DEL              11
#define RAWX_REQ_INFO             12
#define RAWX_REQ_STAT             13
#define RAWX_REQ_RAW              14
#define RAWX_REQ_OTHER            15
#define RAWX_REPLY_2XX            16
#define RAWX_REPLY_4XX            17
#define RAWX_REPLY_5XX            18
#define RAWX_REPLY_403            19
#define RAWX_REPLY_404            20
#define RAWX_REPLY_OTHER          21
#define RAWX_BYTES_READ           22
#define RAWX_BYTES_WRITTEN        23

#define SAVER_NUMBER              0
#define SAVER_INDEX               1
#define SAVER_NAMESPACE           2
#define SAVER_ADDR                3
#define SAVER_SCORE               4
#define SAVER_REQ_PUSH            5
#define SAVER_REQ_STATUS          6
#define SAVER_WORKERS_BYTES       7
#define SAVER_WORKERS_OK          8
#define SAVER_WORKERS_FAILED      9

#define TSMX_NUMBER               0
#define TSMX_INDEX                1
#define TSMX_NAMESPACE            2
#define TSMX_ADDR                 3
#define TSMX_SCORE                4
#define TSMX_IDLE_LOG             5
#define TSMX_IDLE_DB              6
#define TSMX_IDLE_STG             7
#define TSMX_IDLE_DISK            8
#define TSMX_REQ_PUT              9
#define TSMX_REQ_GET              10
#define TSMX_REQ_DEL              11
#define TSMX_FAILED               12
#define TSMX_BYTES_IN             13
#define TSMX_BYTES_OUT            14

#define SOLR_NUMBER		0
#define SOLR_INDEX		1
#define SOLR_NAMESPACE		2
#define SOLR_ADDR		3
#define SOLR_SCORE		4
#define SOLR_REQ_UPDATE		5
#define SOLR_REQ_SEARCH		6
#define SOLR_TIME_UPDATE	7
#define SOLR_TIME_SEARCH	8
#define SOLR_COMMITS		9

#define RPLX_NUMBER		0
#define RPLX_INDEX		1
#define RPLX_NAMESPACE		2
#define RPLX_ADDR		3
#define RPLX_SCORE		4
#define RPLX_NB_THREAD		5
#define RPLX_WORKER_CUR		6
#define RPLX_WORKER_IDLE	7
#define RPLX_WORKER_MAX		8
#define RPLX_WORKER_QUEUE	9
#define RPLX_REQ_PUSH		10
#define RPLX_REQ_STATUS		11
#define RPLX_REQ_TOTAL		12
#define RPLX_TIME_PUSH		13
#define RPLX_TIME_STATUS	14
#define RPLX_TIME_TOTAL		15

#define EVT_NUMBER		0
#define EVT_INDEX		1
#define EVT_NAMESPACE		2
#define EVT_INCOMING_NB		3
#define EVT_INCOMING_AGE	4
#define EVT_INCOMING_OLDEST	5
#define EVT_PENDING_NB		6
#define EVT_PENDING_AGE		7
#define EVT_PENDING_OLDEST	8

#define CSC_NUMBER		0
#define CSC_INDEX		1
#define CSC_NAMESPACE		2
#define CSC_ADDR		3
#define CSC_SCORE		4
#define CSC_NB_THREAD		5
#define CSC_NB_RAWX		6
#define CSC_NB_RAWX_ONLINE	7

#ifndef RAWX_STAT_URL          
#define RAWX_STAT_URL                 "rawx.rep"
#endif

#ifndef RAWX_STATKEY_REP_PREFIX
#define RAWX_STATKEY_REP_PREFIX       "rawx.rep"
#endif

#ifndef RAWX_STATKEY_REQ_ALL
#define RAWX_STATKEY_REQ_ALL          RAWX_STATKEY_REQ_PREFIX".all"
#endif

#ifndef RAWX_STATKEY_REQ_GET
#define RAWX_STATKEY_REQ_GET          RAWX_STATKEY_REQ_PREFIX".get"
#endif

#ifndef RAWX_STATKEY_REQ_PUT
#define RAWX_STATKEY_REQ_PUT          RAWX_STATKEY_REQ_PREFIX".put"
#endif

#ifndef RAWX_STATKEY_REQ_DEL
#define RAWX_STATKEY_REQ_DEL          RAWX_STATKEY_REQ_PREFIX".del"
#endif

#ifndef RAWX_STATKEY_REQ_INFO
#define RAWX_STATKEY_REQ_INFO         RAWX_STATKEY_REQ_PREFIX".info"
#endif

#ifndef RAWX_STATKEY_REQ_STAT
#define RAWX_STATKEY_REQ_STAT         RAWX_STATKEY_REQ_PREFIX".stat"
#endif

#ifndef RAWX_STATKEY_REQ_RAW
#define RAWX_STATKEY_REQ_RAW          RAWX_STATKEY_REQ_PREFIX".raw"
#endif

#ifndef RAWX_STATKEY_REQ_OTHER
#define RAWX_STATKEY_REQ_OTHER        RAWX_STATKEY_REQ_PREFIX".other"
#endif

#ifndef RAWX_STATKEY_REQ_PREFIX
#define RAWX_STATKEY_REQ_PREFIX       "rawx.req"
#endif

#ifndef RAWX_STATKEY_REP_2XX
#define RAWX_STATKEY_REP_2XX          RAWX_STATKEY_REP_PREFIX".2xx"
#endif

#ifndef RAWX_STATKEY_REP_4XX
#define RAWX_STATKEY_REP_4XX          RAWX_STATKEY_REP_PREFIX".4xx"
#endif

#ifndef RAWX_STATKEY_REP_5XX
#define RAWX_STATKEY_REP_5XX          RAWX_STATKEY_REP_PREFIX".5xx"
#endif

#ifndef RAWX_STATKEY_REP_403
#define RAWX_STATKEY_REP_403          RAWX_STATKEY_REP_PREFIX".403"
#endif

#ifndef RAWX_STATKEY_REP_404
#define RAWX_STATKEY_REP_404          RAWX_STATKEY_REP_PREFIX".404"
#endif

#ifndef RAWX_STATKEY_REP_OTHER
#define RAWX_STATKEY_REP_OTHER        RAWX_STATKEY_REP_PREFIX".other"
#endif

#ifndef RAWX_STATKEY_BYTES_READ
#define RAWX_STATKEY_BYTES_READ       RAWX_STATKEY_REP_PREFIX".bread"
#endif

#ifndef RAWX_STATKEY_BYTES_WRITTEN    
#define RAWX_STATKEY_BYTES_WRITTEN    RAWX_STATKEY_REP_PREFIX".bwritten"
#endif

#ifndef META2_STAT_REQ_TOTAL
#define META2_STAT_REQ_TOTAL        "meta2.req.gauge.total"
#endif
#ifndef META2_STAT_REQ_TOTAL_V2
#define META2_STAT_REQ_TOTAL_V2     "gridd.counter.allreq"
#endif
#ifndef META2_STAT_REQ_FAIL
#define META2_STAT_REQ_FAIL         "meta2.req.gauge.failures"
#endif

#ifndef META2_STAT_REQ_CREATE
#define META2_STAT_REQ_CREATE       "meta2.req.gauge.create"
#endif
#ifndef META2_STAT_REQ_CREATE_V1
#define META2_STAT_REQ_CREATE_V1    "gridd.counter.req.REQ_M2_CREATE"
#endif
#ifndef META2_STAT_REQ_CREATE_V2
#define META2_STAT_REQ_CREATE_V2    "gridd.counter.req.M2V2_CREATE"
#endif
#ifndef META2_STAT_REQ_OPEN
#define META2_STAT_REQ_OPEN         "meta2.req.gauge.open"
#endif
#ifndef META2_STAT_REQ_OPEN_V2
#define META2_STAT_REQ_OPEN_V2      "gridd.counter.req.REQ_M2_OPEN"
#endif
#ifndef META2_STAT_REQ_CLOSE
#define META2_STAT_REQ_CLOSE        "meta2.req.gauge.close"
#endif
#ifndef META2_STAT_REQ_CLOSE_V2
#define META2_STAT_REQ_CLOSE_V2     "gridd.counter.req.REQ_M2_CLOSE"
#endif
#ifndef META2_STAT_REQ_DESTROY
#define META2_STAT_REQ_DESTROY      "meta2.req.gauge.destroy"
#endif
#ifndef META2_STAT_REQ_DESTROY_V1
#define META2_STAT_REQ_DESTROY_V1   "gridd.counter.req.REQ_M2_DESTROY"
#endif
#ifndef META2_STAT_REQ_DESTROY_V2
#define META2_STAT_REQ_DESTROY_V2   "gridd.counter.req.M2V2_DESTROY"
#endif

#ifndef META2_STAT_REQ_LIST
#define META2_STAT_REQ_LIST         "meta2.req.gauge.list"
#endif
#ifndef META2_STAT_REQ_LIST_V1
#define META2_STAT_REQ_LIST_V1      "gridd.counter.req.REQ_M2_LIST"
#endif
#ifndef META2_STAT_REQ_LIST_V2
#define META2_STAT_REQ_LIST_V2      "gridd.counter.req.M2V2_LIST"
#endif
#ifndef META2_STAT_REQ_CONTENT_RET
#define META2_STAT_REQ_CONTENT_RET  "meta2.req.gauge.content_retrieve"
#endif
#ifndef META2_STAT_REQ_CONTENT_RET_V1
#define META2_STAT_REQ_CONTENT_RET_V1  "gridd.counter.req.REQ_M2_CONTENTRETRIEVE"
#endif
#ifndef META2_STAT_REQ_CONTENT_RET_V2
#define META2_STAT_REQ_CONTENT_RET_V2  "gridd.counter.req.M2V2_GET"
#endif
#ifndef META2_STAT_REQ_CONTENT_RM
#define META2_STAT_REQ_CONTENT_RM   "meta2.req.gauge.content_remove"
#endif
#ifndef META2_STAT_REQ_CONTENT_RM_V1
#define META2_STAT_REQ_CONTENT_RM_V1 "gridd.counter.req.REQ_M2_CONTENTREMOVE"
#endif
#ifndef META2_STAT_REQ_CONTENT_RM_V2
#define META2_STAT_REQ_CONTENT_RM_V2 "gridd.counter.req.M2V2_DEL"
#endif
#ifndef META2_STAT_REQ_CONTENT_ADD
#define META2_STAT_REQ_CONTENT_ADD    "meta2.req.gauge.content_add"
#endif
#ifndef META2_STAT_REQ_CONTENT_ADD_V1
#define META2_STAT_REQ_CONTENT_ADD_V1  "gridd.counter.req.REQ_M2_CONTENTADD"
#endif
#ifndef META2_STAT_REQ_CONTENT_ADD_V2
#define META2_STAT_REQ_CONTENT_ADD_V2  "gridd.counter.req.M2V2_PUT"
#endif
#ifndef META2_STAT_REQ_CONTENT_APPEND
#define META2_STAT_REQ_CONTENT_APPEND "meta2.req.gauge.content_append"
#endif
#ifndef META2_STAT_REQ_CONTENT_APPEND_V1
#define META2_STAT_REQ_CONTENT_APPEND_V1 "gridd.counter.req.REQ_M2_CONTENTAPPEND"
#endif
#ifndef META2_STAT_REQ_CONTENT_APPEND_V2
#define META2_STAT_REQ_CONTENT_APPEND_V2 "gridd.counter.req.M2V2_APPEND"
#endif
#ifndef META2_STAT_REQ_CONTENT_COMMIT
#define META2_STAT_REQ_CONTENT_COMMIT "meta2.req.gauge.content_commit"
#endif
#ifndef META2_STAT_REQ_CONTENT_COMMIT_V1
#define META2_STAT_REQ_CONTENT_COMMIT_V1 "gridd.counter.req.REQ_M2_CONTENTCOMMIT"
#endif
#ifndef META2_STAT_REQ_CHUNK_COMMIT
#define META2_STAT_REQ_CHUNK_COMMIT   "meta2.req.gauge.chunks_commit"
#endif
#ifndef META2_STAT_REQ_CHUNK_COMMIT_V1
#define META2_STAT_REQ_CHUNK_COMMIT_V1   "gridd.counter.req.REQ_M2_CHUNK_COMMIT"
#endif

#ifndef META2_STAT_REQ_RAW_GETCONTENT
#define META2_STAT_REQ_RAW_GETCONTENT "meta2.req.counter.maintenance_getcontent"
#endif
#ifndef META2_STAT_REQ_RAW_GETCONTENT_V1
#define META2_STAT_REQ_RAW_GETCONTENT_V1 "gridd.counter.req.REQ_M2RAW_CONTENT_GET"
#endif
#ifndef META2_STAT_REQ_RAW_GETCHUNK
#define META2_STAT_REQ_RAW_GETCHUNK   "meta2.req.counter.maintenance_getchunks"
#endif
#ifndef META2_STAT_REQ_RAW_GETCHUNK_V1
#define META2_STAT_REQ_RAW_GETCHUNK_V1   "gridd.counter.req.REQ_M2RAW_CHUNKS_GET"
#endif
#ifndef META2_STAT_REQ_RAW_SETCONTENT
#define META2_STAT_REQ_RAW_SETCONTENT "meta2.req.counter.maintenance_setcontent"
#endif
#ifndef META2_STAT_REQ_RAW_SETCONTENT_V1
#define META2_STAT_REQ_RAW_SETCONTENT_V1 "gridd.counter.req.REQ_M2RAW_CONTENT_SET"
#endif
#ifndef META2_STAT_REQ_RAW_SETCHUNK
#define META2_STAT_REQ_RAW_SETCHUNK   "meta2.req.counter.maintenance_setchunks"
#endif
#ifndef META2_STAT_REQ_RAW_SETCHUNK_V1
#define META2_STAT_REQ_RAW_SETCHUNK_V1   "gridd.counter.req.REQ_M2RAW_CHUNKS_SET"
#endif
#ifndef META2_STAT_REQ_RAW_DELCONTENT
#define META2_STAT_REQ_RAW_DELCONTENT "meta2.req.counter.maintenance_delcontent"
#endif
#ifndef META2_STAT_REQ_RAW_DELCONTENT_V1
#define META2_STAT_REQ_RAW_DELCONTENT_V1 "gridd.counter.req.REQ_M2RAW_CONTENT_DEL"
#endif
#ifndef META2_STAT_REQ_RAW_DELCHUNK
#define META2_STAT_REQ_RAW_DELCHUNK   "meta2.req.counter.maintenance_delchunks"
#endif
#ifndef META2_STAT_REQ_RAW_DELCHUNK_V1
#define META2_STAT_REQ_RAW_DELCHUNK_V1   "gridd.counter.req.REQ_M2RAW_CHUNKS_DEL"
#endif
#ifndef META2_STAT_REQ_RAW_OTHER
#define META2_STAT_REQ_RAW_OTHER      "meta2.req.counter.maintenance_other"
#endif

#ifndef META2_STAT_TIME_CREATE
#define META2_STAT_TIME_CREATE      "meta2.req.time.create"
#endif
#ifndef META2_STAT_TIME_CREATE_V1
#define META2_STAT_TIME_CREATE_V1   "gridd.counter.time.REQ_M2_CREATE"
#endif
#ifndef META2_STAT_TIME_CREATE_V2
#define META2_STAT_TIME_CREATE_V2   "gridd.counter.time.M2V2_CREATE"
#endif
#ifndef META2_STAT_TIME_OPEN
#define META2_STAT_TIME_OPEN        "meta2.req.time.open"
#endif
#ifndef META2_STAT_TIME_OPEN_V1
#define META2_STAT_TIME_OPEN_V1        "gridd.counter.time.REQ_M2_OPEN"
#endif
#ifndef META2_STAT_TIME_CLOSE
#define META2_STAT_TIME_CLOSE       "meta2.req.time.close"
#endif
#ifndef META2_STAT_TIME_CLOSE_V1
#define META2_STAT_TIME_CLOSE_V1       "gridd.counter.time.REQ_M2_CLOSE"
#endif
#ifndef META2_STAT_TIME_DESTROY
#define META2_STAT_TIME_DESTROY     "meta2.req.time.destroy"
#endif
#ifndef META2_STAT_TIME_DESTROY_V1
#define META2_STAT_TIME_DESTROY_V1     "gridd.counter.time.REQ_M2_DESTROY"
#endif
#ifndef META2_STAT_TIME_DESTROY_V2
#define META2_STAT_TIME_DESTROY_V2  "gridd.counter.time.M2V2_DESTROY"
#endif

#ifndef META2_STAT_TIME_LIST
#define META2_STAT_TIME_LIST           "meta2.req.time.list"
#endif
#ifndef META2_STAT_TIME_LIST_V1
#define META2_STAT_TIME_LIST_V1        "gridd.counter.time.REQ_M2_LIST"
#endif
#ifndef META2_STAT_TIME_LIST_V2
#define META2_STAT_TIME_LIST_V2        "gridd.counter.time.M2V2_LIST"
#endif
#ifndef META2_STAT_TIME_CONTENT_RM
#define META2_STAT_TIME_CONTENT_RM     "meta2.req.time.content_remove"
#endif
#ifndef META2_STAT_TIME_CONTENT_RM_V1
#define META2_STAT_TIME_CONTENT_RM_V1  "gridd.counter.time.REQ_M2_CONTENTREMOVE"
#endif
#ifndef META2_STAT_TIME_CONTENT_RM_V2
#define META2_STAT_TIME_CONTENT_RM_V2  "gridd.counter.time.M2V2_DEL"
#endif
#ifndef META2_STAT_TIME_CONTENT_RET    
#define META2_STAT_TIME_CONTENT_RET    "meta2.req.time.content_retrieve"
#endif
#ifndef META2_STAT_TIME_CONTENT_RET_V1
#define META2_STAT_TIME_CONTENT_RET_V1 "gridd.counter.time.REQ_M2RAW_CHUNKS_GET"
#endif
#ifndef META2_STAT_TIME_CONTENT_RET_V2    
#define META2_STAT_TIME_CONTENT_RET_V2 "gridd.counter.time.M2V2_GET"
#endif
#ifndef META2_STAT_TIME_CONTENT_ADD    
#define META2_STAT_TIME_CONTENT_ADD    "meta2.req.time.content_add"
#endif
#ifndef META2_STAT_TIME_CONTENT_ADD_V1
#define META2_STAT_TIME_CONTENT_ADD_V1  "gridd.counter.time.REQ_M2_CONTENTADD"
#endif
#ifndef META2_STAT_TIME_CONTENT_ADD_V2    
#define META2_STAT_TIME_CONTENT_ADD_V2 "gridd.counter.time.M2V2_PUT"
#endif
#ifndef META2_STAT_TIME_CONTENT_APPEND
#define META2_STAT_TIME_CONTENT_APPEND "meta2.req.time.content_append"
#endif
#ifndef META2_STAT_TIME_CONTENT_APPEND_V1
#define META2_STAT_TIME_CONTENT_APPEND_V1 "gridd.counter.time.REQ_M2_CONTENTAPPEND"
#endif
#ifndef META2_STAT_TIME_CONTENT_APPEND_V2
#define META2_STAT_TIME_CONTENT_APPEND_V2 "gridd.counter.time.M2V2_APPEND"
#endif
#ifndef META2_STAT_TIME_CHUNK_CI
#define META2_STAT_TIME_CHUNK_CI       "meta2.req.time.chunks_commit"
#endif
#ifndef META2_STAT_TIME_CHUNK_CI_V1
#define META2_STAT_TIME_CHUNK_CI_V1    "gridd.counter.time.REQ_M2_CHUNK_COMMIT"
#endif
#ifndef META2_STAT_TIME_CONTENT_CI
#define META2_STAT_TIME_CONTENT_CI     "meta2.req.time.content_commit"
#endif
#ifndef META2_STAT_TIME_CONTENT_CI_V1
#define META2_STAT_TIME_CONTENT_CI_V1  "gridd.counter.time.REQ_M2_CONTENTCOMMIT"
#endif

#ifndef META2_STAT_TIME_RAW_GETCONTENT
#define META2_STAT_TIME_RAW_GETCONTENT "meta2.req.time.maintenance_getcontent"
#endif
#ifndef META2_STAT_TIME_RAW_GETCONTENT_V1
#define META2_STAT_TIME_RAW_GETCONTENT_V1 "gridd.counter.time.REQ_M2RAW_CONTENT_GET"
#endif
#ifndef META2_STAT_TIME_RAW_GETCHUNK
#define META2_STAT_TIME_RAW_GETCHUNK   "meta2.req.time.maintenance_getchunks"
#endif
#ifndef META2_STAT_TIME_RAW_GETCHUNK_V1
#define META2_STAT_TIME_RAW_GETCHUNK_V1   "gridd.counter.time.REQ_M2RAW_CHUNKS_GET"
#endif
#ifndef META2_STAT_TIME_RAW_SETCONTENT
#define META2_STAT_TIME_RAW_SETCONTENT "meta2.req.time.maintenance_setcontent"
#endif
#ifndef META2_STAT_TIME_RAW_SETCONTENT_V1
#define META2_STAT_TIME_RAW_SETCONTENT_V1 "gridd.counter.time.REQ_M2RAW_CONTENT_SET"
#endif
#ifndef META2_STAT_TIME_RAW_SETCHUNK
#define META2_STAT_TIME_RAW_SETCHUNK   "meta2.req.time.maintenance_setchunks"
#endif
#ifndef META2_STAT_TIME_RAW_SETCHUNK_V1
#define META2_STAT_TIME_RAW_SETCHUNK_V1   "gridd.counter.time.REQ_M2RAW_CHUNKS_SET"
#endif
#ifndef META2_STAT_TIME_RAW_DELCONTENT
#define META2_STAT_TIME_RAW_DELCONTENT "meta2.req.time.maintenance_delcontent"
#endif
#ifndef META2_STAT_TIME_RAW_DELCONTENT_V1
#define META2_STAT_TIME_RAW_DELCONTENT_V1 "gridd.counter.time.REQ_M2RAW_CONTENT_DEL"
#endif
#ifndef META2_STAT_TIME_RAW_DELCHUNK
#define META2_STAT_TIME_RAW_DELCHUNK   "meta2.req.time.maintenance_delchunks"
#endif
#ifndef META2_STAT_TIME_RAW_DELCHUNK_V1
#define META2_STAT_TIME_RAW_DELCHUNK_V1   "gridd.counter.time.REQ_M2RAW_CHUNKS_DEL"
#endif
#ifndef META2_STAT_TIME_RAW_OTHER
#define META2_STAT_TIME_RAW_OTHER      "meta2.req.time.maintenance_other"
#endif

#ifndef META2_STAT_REQ_RPLCONTENT
#define META2_STAT_REQ_RPLCONTENT      "meta2_services.req_counter.replicate_content_v2"
#endif
#ifndef META2_STAT_TIME_RPLCONTENT
#define META2_STAT_TIME_RPLCONTENT     "meta2_services.req_time.replicate_content_v2"
#endif
#ifndef META2_STAT_REQ_STATCONTENT
#define META2_STAT_REQ_STATCONTENT     "meta2_services.req_counter.stat_content_v2"
#endif
#ifndef META2_STAT_TIME_STATCONTENT
#define META2_STAT_TIME_STATCONTENT    "meta2_services.req_time.stat_content_v2"
#endif

#ifndef META2_STAT_NB_THREAD
#define META2_STAT_NB_THREAD           "server.cnx.gauge.total"
#endif
#ifndef META2_STAT_NB_THREAD_V2
#define META2_STAT_NB_THREAD_V2        "server.thread.gauge.total"
#endif

#ifndef META2_STAT_REQ_PROP_GET_CONTAINER
#define META2_STAT_REQ_PROP_GET_CONTAINER "meta2_services.req_counter.get_container_property"
#endif
#ifndef META2_STAT_REQ_PROP_GET_CONTENT
#define META2_STAT_REQ_PROP_GET_CONTENT "meta2_services.req_counter.get_content_property"
#endif
#ifndef META2_STAT_REQ_PROP_RM_CONTAINER
#define META2_STAT_REQ_PROP_RM_CONTAINER "meta2_services.req_counter.remove_container_property"
#endif
#ifndef META2_STAT_REQ_PROP_RM_CONTENT
#define META2_STAT_REQ_PROP_RM_CONTENT "meta2_services.req_counter.remove_content_property"
#endif
#ifndef META2_STAT_REQ_PROP_RPL_RM_CONTAINER
#define META2_STAT_REQ_PROP_RPL_RM_CONTAINER "meta2_services.req_counter.replicate_remove_container_property"
#endif
#ifndef META2_STAT_REQ_PROP_RPL_SET_CONTAINER
#define META2_STAT_REQ_PROP_RPL_SET_CONTAINER "meta2_services.req_counter.replicate_set_container_property"
#endif
#ifndef META2_STAT_REQ_PROP_SET_CONTAINER
#define META2_STAT_REQ_PROP_SET_CONTAINER "meta2_services.req_counter.set_container_property"
#endif
#ifndef META2_STAT_REQ_PROP_SET_CONTENT
#define META2_STAT_REQ_PROP_SET_CONTENT "meta2_services.req_counter.set_content_property"
#endif
#ifndef META2_STAT_TIME_PROP_GET_CONTAINER
#define META2_STAT_TIME_PROP_GET_CONTAINER "meta2_services.req_time.get_container_property"
#endif
#ifndef META2_STAT_TIME_PROP_GET_CONTENT
#define META2_STAT_TIME_PROP_GET_CONTENT "meta2_services.req_time.get_content_property"
#endif
#ifndef META2_STAT_TIME_PROP_RM_CONTAINER
#define META2_STAT_TIME_PROP_RM_CONTAINER "meta2_services.req_time.remove_container_property"
#endif
#ifndef META2_STAT_TIME_PROP_RM_CONTENT
#define META2_STAT_TIME_PROP_RM_CONTENT "meta2_services.req_time.remove_content_property"
#endif
#ifndef META2_STAT_TIME_PROP_RPL_RM_CONTAINER
#define META2_STAT_TIME_PROP_RPL_RM_CONTAINER "meta2_services.req_time.replicate_remove_container_property"
#endif
#ifndef META2_STAT_TIME_PROP_RPL_SET_CONTAINER
#define META2_STAT_TIME_PROP_RPL_SET_CONTAINER "meta2_services.req_time.replicate_set_container_property"
#endif
#ifndef META2_STAT_TIME_PROP_SET_CONTAINER
#define META2_STAT_TIME_PROP_SET_CONTAINER "meta2_services.req_time.set_container_property"
#endif
#ifndef META2_STAT_TIME_PROP_SET_CONTENT
#define META2_STAT_TIME_PROP_SET_CONTENT "meta2_services.req_time.set_content_property"
#endif

/* ------------------------------------------------------------------------- */

#ifndef TSMX_STAT_URL
#define TSMX_STAT_URL               "/stat"
#endif
#ifndef TSMX_STATKEY_REQ_PUT
#define TSMX_STATKEY_REQ_PUT        "tsmx.req_put"
#endif
#ifndef TSMX_STATKEY_REQ_GET
#define TSMX_STATKEY_REQ_GET        "tsmx.req_get"
#endif
#ifndef TSMX_STATKEY_REQ_DEL
#define TSMX_STATKEY_REQ_DEL        "tsmx.req_del"
#endif
#ifndef TSMX_STATKEY_FAILED
#define TSMX_STATKEY_FAILED         "tsmx.req_failed"
#endif
#ifndef TSMX_STATKEY_BYTES_IN
#define TSMX_STATKEY_BYTES_IN       "tsmx.bytes_in"
#endif
#ifndef TSMX_STATKEY_BYTES_OUT
#define TSMX_STATKEY_BYTES_OUT      "tsmx.bytes_out"
#endif

/* ------------------------------------------------------------------------- */

#ifndef SAVER_STAT_REQ_STATUS
#define SAVER_STAT_REQ_STATUS      "saver.counters.request.status"
#endif
#ifndef SAVER_STAT_REQ_PUSH
#define SAVER_STAT_REQ_PUSH        "saver.counters.request.push"
#endif
#ifndef SAVER_STAT_BYTES
#define SAVER_STAT_BYTES           "saver.counters.workers.bytes"
#endif
#ifndef SAVER_STAT_WORKER_OK
#define SAVER_STAT_WORKER_OK       "saver.counters.workers.success"
#endif
#ifndef SAVER_STAT_WORKER_KO
#define SAVER_STAT_WORKER_KO       "saver.counters.workers.failure"
#endif

/* ------------------------------------------------------------------------- */

#ifndef SOLR_STAT_URL
#define SOLR_STAT_URL	               "/solr/admin/stats-grid.jsp"
#endif

#ifndef SOLR_STATKEY_REQ_UPDATE
#define SOLR_STATKEY_REQ_UPDATE		"/update.org.apache.solr.handler.XmlUpdateRequestHandler.avgRequestsPerSecond"
#endif

#ifndef SOLR_STATKEY_TIME_UPDATE
#define SOLR_STATKEY_TIME_UPDATE	"/update.org.apache.solr.handler.XmlUpdateRequestHandler.avgTimePerRequest"
#endif

#ifndef SOLR_STATKEY_REQ_SEARCH
#define SOLR_STATKEY_REQ_SEARCH		"search.org.apache.solr.handler.component.SearchHandler.avgRequestsPerSecond"
#endif

#ifndef SOLR_STATKEY_TIME_SEARCH
#define SOLR_STATKEY_TIME_SEARCH	"search.org.apache.solr.handler.component.SearchHandler.avgTimePerRequest"
#endif

#ifndef SOLR_STATKEY_COMMITS
#define SOLR_STATKEY_COMMITS		"updateHandler.org.apache.solr.update.DirectUpdateHandler2.commits"
#endif

/* ------------------------------------------------------------------------- */

#ifndef RPLX_STAT_WORKERS_CUR
#define RPLX_STAT_WORKERS_CUR		"replicator.gauge.workers.current"
#endif

#ifndef RPLX_STAT_WORKERS_IDLE
#define RPLX_STAT_WORKERS_IDLE		"replicator.gauge.workers.idle"
#endif

#ifndef RPLX_STAT_WORKERS_MAX
#define RPLX_STAT_WORKERS_MAX		"replicator.gauge.workers.max"
#endif

#ifndef RPLX_STAT_WORKERS_QUEUE
#define RPLX_STAT_WORKERS_QUEUE		"replicator.gauge.workers.queue"
#endif

#ifndef RPLX_STAT_REQ_PUSH
#define RPLX_STAT_REQ_PUSH		"replicator.counter.request.push"
#endif

#ifndef RPLX_STAT_REQ_STATUS
#define RPLX_STAT_REQ_STATUS		"replicator.counter.request.status"
#endif

#ifndef RPLX_STAT_REQ_TOTAL
#define RPLX_STAT_REQ_TOTAL		"replicator.counter.request.total"
#endif

#ifndef RPLX_STAT_TIMES_PUSH
#define RPLX_STAT_TIMES_PUSH		"replicator.gauge.times.push"
#endif

#ifndef RPLX_STAT_TIMES_STATUS
#define RPLX_STAT_TIMES_STATUS		"replicator.gauge.times.status"
#endif

#ifndef RPLX_STAT_TIMES_TOTAL
#define RPLX_STAT_TIMES_TOTAL		"replicator.gauge.times.total"
#endif

#ifndef RPLX_STAT_NB_THREAD
#define RPLX_STAT_NB_THREAD		"server.cnx.gauge.total"
#endif

/* ------------------------------------------------------------------------- */

#ifndef CSC_STAT_NB_THREAD
#define CSC_STAT_NB_THREAD        "server.cnx.gauge.total"
#endif

/* ------------------------------------------------------------------------- */

#ifndef SOCK_TIMEOUT
#define SOCK_TIMEOUT 1000
#endif

#ifndef MAX_SRV
#define MAX_SRV 512
#endif

#endif	/* _GRID_STORAGE_H */
