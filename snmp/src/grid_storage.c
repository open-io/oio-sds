#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.snmp.gridstorage"
#endif

#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <cluster/remote/gridcluster_remote.h>
#include <gridd/clients/stats/stats_remote.h>

#include "session.h"
#include "grid_storage.h"
#include "idx_management.h"
#include "events.h"

/* ------------------------------------------------------------------------- */

extern int header_generic(struct variable * vp, oid * name, size_t * length,
		int exact, size_t * var_len, WriteMethod ** write_method);

extern int header_simple_table(struct variable * vp, oid * name, size_t * length,
		int exact, size_t * var_len, WriteMethod ** write_method, int);

static void manage_meta2(struct service_info_s *si);
static struct meta2_snmp_data *meta2_snmp_data[MAX_SRV];
static int meta2_max_index = 0;
static int meta2_count = 0;

static void manage_saver(struct service_info_s *si);
static struct saver_snmp_data *saver_snmp_data[MAX_SRV];
static int saver_max_index = 0;
static int saver_count = 0;

static void manage_rawx(struct service_info_s *si);
static struct rawx_snmp_data *rawx_snmp_data[MAX_SRV];
static int rawx_max_index = 0;
static int rawx_count = 0;

static void manage_tsmx(struct service_info_s *si);
static struct tsmx_snmp_data *tsmx_snmp_data[MAX_SRV];
static int tsmx_max_index = 0;
static int tsmx_count = 0;

static void manage_solr(struct service_info_s *si);
static struct solr_snmp_data *solr_snmp_data[MAX_SRV];
static int solr_max_index = 0;
static int solr_count = 0;

static void manage_rplx(struct service_info_s *si);
static struct rplx_snmp_data *rplx_snmp_data[MAX_SRV];
static int rplx_max_index = 0;
static int rplx_count = 0;

static void manage_evt(const gchar * ns_name);
static struct evt_snmp_data *evt_snmp_data[MAX_SRV];
static int evt_max_index = 0;
static int evt_count = 0;
static char evt_spool_dir[PATH_MAX];

static void manage_csc(const gchar * ns_name);
static struct csc_snmp_data *csc_snmp_data[MAX_SRV];
static int csc_max_index = 0;
static int csc_count = 0;
static GSList *csc_ns_list = NULL;

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

static void
oid_to_string(oid *name, size_t name_len, char *dst, size_t dst_size)
{
	size_t i, dst_i;

	dst_i = 0;
	bzero(dst, dst_size);

	for (i=0; i<name_len ;i++) {
		gint64 i64 = name[i];
		dst_i += g_snprintf(dst+dst_i, dst_size-dst_i, ".%"G_GINT64_FORMAT, i64);
		if (dst_i > dst_size)
			return;
	}
}

/* ------------------------------------------------------------------------- */

static void
config_parser(const char * key, char * value)
{
	gchar **ns_list = NULL;
	int i;

	if (key == NULL)
		return;

	if (!g_ascii_strncasecmp(key, "CollectConscience", strlen("CollectConscience"))) {
		ns_list = g_strsplit(value, ",", 0);
		for (i = 0; ns_list[i] != NULL; i++)
			csc_ns_list = g_slist_prepend(csc_ns_list, g_strdup(ns_list[i]));
		g_strfreev(ns_list);
	}
	else if (!g_ascii_strncasecmp(key, "GridEventSpoolDir", strlen("GridEventSpoolDir"))) {
		g_strlcpy(evt_spool_dir, value, sizeof(evt_spool_dir));
	}
}

static void
register_config(void)
{
	/* Init var and set defaults */
	csc_ns_list = NULL;
	memset(evt_spool_dir, '\0', sizeof(evt_spool_dir));
	g_strlcpy(evt_spool_dir, SPOOLDIR, sizeof(evt_spool_dir));

	register_app_config_handler("CollectConscience", config_parser, NULL, "A coma separated list of ns names");
	register_app_config_handler("GridEventSpoolDir", config_parser, NULL, "A path");
}


/* ------------------------------------------------------------------------- */

void
init_grid_storage(void)
{
	register_config();

	struct variable4 meta2_variables[] = {
		{META2_NUMBER,               ASN_INTEGER,   RONLY, var_meta2_number, 1, {1}},
		{META2_INDEX,                ASN_INTEGER,   RONLY, var_meta2_entry,  3, {2, 1, 1}},
		{META2_NAMESPACE,            ASN_OCTET_STR, RONLY, var_meta2_entry,  3, {2, 1, 2}},

		{META2_REQ_TOTAL,            ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 1}},
		{META2_REQ_CREATE,           ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 2}},
		{META2_REQ_ALLGETS,          ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 3}},
		{META2_REQ_LIST,             ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 4}},
		{META2_REQ_CLOSE,            ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 5}},
		{META2_REQ_DESTROY,          ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 6}},
		{META2_REQ_CONTENT_RM,       ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 7}},
		{META2_REQ_OPEN,             ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 8}},
		{META2_REQ_FAIL,             ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 9}},
		{META2_REQ_CONTENT_ALLPUTS,  ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 10}},
		{META2_REQ_CONTENT_ADD,      ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 11}},
		{META2_REQ_CONTENT_APPEND,   ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 12}},
		{META2_REQ_CONTENT_COMMIT,   ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 13}},
		{META2_REQ_CHUNK_COMMIT,     ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 14}},
		{META2_REQ_CONTENT_GET,      ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 15}},
		{META2_REQ_RPLCONTENT,       ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 16}},
		{META2_REQ_STATCONTENT,      ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 3, 17}},

		{META2_TIME_CREATE,          ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 1}},
		{META2_TIME_ALLGETS,         ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 2}},
		{META2_TIME_LIST,            ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 3}},
		{META2_TIME_CLOSE,           ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 4}},
		{META2_TIME_DESTROY,         ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 5}},
		{META2_TIME_CONTENT_RM,      ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 6}},
		{META2_TIME_OPEN,            ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 7}},
		{META2_TIME_CONTENT_ALLPUTS, ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 8}},
		{META2_TIME_CONTENT_ADD,     ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 9}},
		{META2_TIME_CONTENT_APPEND,  ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 10}},
		{META2_TIME_CONTENT_COMMIT,  ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 11}},
		{META2_TIME_CHUNK_COMMIT,    ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 12}},
		{META2_TIME_CONTENT_GET,     ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 13}},
		{META2_TIME_RPLCONTENT,      ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 14}},
		{META2_TIME_STATCONTENT,     ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 4, 15}},

		{META2_ADDR,                 ASN_OCTET_STR, RONLY, var_meta2_entry,  3, {2, 1, 5}},
		{META2_NB_THREAD,            ASN_GAUGE,     RONLY, var_meta2_entry,  3, {2, 1, 6}},
		{META2_SCORE,                ASN_INTEGER,   RONLY, var_meta2_entry,  3, {2, 1, 7}},

		{META2_REQ_RAW_GETCONTENT,   ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 1}},
		{META2_REQ_RAW_GETCHUNK,     ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 2}},
		{META2_REQ_RAW_SETCONTENT,   ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 3}},
		{META2_REQ_RAW_SETCHUNK,     ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 4}},
		{META2_REQ_RAW_DELCONTENT,   ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 5}},
		{META2_REQ_RAW_DELCHUNK,     ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 6}},
		{META2_REQ_RAW_OTHER,        ASN_COUNTER,   RONLY, var_meta2_entry,  4, {2, 1, 8, 7}},

		{META2_TIME_RAW_GETCONTENT,  ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 1}},
		{META2_TIME_RAW_GETCHUNK,    ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 2}},
		{META2_TIME_RAW_SETCONTENT,  ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 3}},
		{META2_TIME_RAW_SETCHUNK,    ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 4}},
		{META2_TIME_RAW_DELCONTENT,  ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 5}},
		{META2_TIME_RAW_DELCHUNK,    ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 6}},
		{META2_TIME_RAW_OTHER,       ASN_GAUGE,     RONLY, var_meta2_entry,  4, {2, 1, 9, 7}},

		{META2_REQ_PROP_SET_CONTENT,	   ASN_COUNTER,	 RONLY,  var_meta2_entry, 4, {2, 1, 10, 1}},
		{META2_REQ_PROP_SET_CONTAINER,     ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 2}},
		{META2_REQ_PROP_GET_CONTENT,       ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 3}},
		{META2_REQ_PROP_GET_CONTAINER,     ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 4}},
		{META2_REQ_PROP_RM_CONTENT,        ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 5}},
		{META2_REQ_PROP_RM_CONTAINER,      ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 6}},
		{META2_REQ_PROP_RPL_SET_CONTAINER, ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 7}},
		{META2_REQ_PROP_RPL_RM_CONTAINER,  ASN_COUNTER,  RONLY,  var_meta2_entry, 4, {2, 1, 10, 8}},

		{META2_TIME_PROP_SET_CONTENT,	    ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 1}},
		{META2_TIME_PROP_SET_CONTAINER,     ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 2}},
		{META2_TIME_PROP_GET_CONTENT,       ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 3}},
		{META2_TIME_PROP_GET_CONTAINER,     ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 4}},
		{META2_TIME_PROP_RM_CONTENT,        ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 5}},
		{META2_TIME_PROP_RM_CONTAINER,      ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 6}},
		{META2_TIME_PROP_RPL_SET_CONTAINER, ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 7}},
		{META2_TIME_PROP_RPL_RM_CONTAINER,  ASN_GAUGE,   RONLY,  var_meta2_entry, 4, {2, 1, 11, 8}}
	};

	struct variable4 rawx_variables[] = {
		{RAWX_NUMBER,     ASN_INTEGER,   RONLY, var_rawx_number, 1, {1}},
		{RAWX_INDEX,      ASN_INTEGER,   RONLY, var_rawx_entry,  3, {2, 1, 1}},
		{RAWX_NAMESPACE,  ASN_OCTET_STR, RONLY, var_rawx_entry,  3, {2, 1, 2}},
		{RAWX_VOLUME,     ASN_OCTET_STR, RONLY, var_rawx_entry,  3, {2, 1, 3}},
		{RAWX_ADDR,       ASN_OCTET_STR, RONLY, var_rawx_entry,  3, {2, 1, 4}},
		{RAWX_FREE_CHUNK, ASN_INTEGER,   RONLY, var_rawx_entry,  4, {2, 1, 5, 1}},
		{RAWX_IO_IDLE,    ASN_INTEGER,   RONLY, var_rawx_entry,  4, {2, 1, 5, 2}},
		{RAWX_SCORE,      ASN_INTEGER,   RONLY, var_rawx_entry,  3, {2, 1, 6}},
		{RAWX_REQ_ALL,     ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 1}},
		{RAWX_REQ_GET,     ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 2}},
		{RAWX_REQ_PUT,     ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 3}},
		{RAWX_REQ_DEL,     ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 4}},
		{RAWX_REQ_INFO,    ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 5}},
		{RAWX_REQ_STAT,    ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 6}},
		{RAWX_REQ_RAW,     ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 7}},
		{RAWX_REQ_OTHER,   ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 8}},
		{RAWX_REPLY_2XX,   ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 9}},
		{RAWX_REPLY_4XX,   ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 10}},
		{RAWX_REPLY_5XX,   ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 11}},
		{RAWX_REPLY_403,   ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 12}},
		{RAWX_REPLY_404,   ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 13}},
		{RAWX_REPLY_OTHER, ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 14}},
		{RAWX_BYTES_READ,  ASN_COUNTER, RONLY, var_rawx_entry,   4, {2, 1, 7, 15}},
		{RAWX_BYTES_WRITTEN, ASN_COUNTER, RONLY, var_rawx_entry, 4, {2, 1, 7, 16}}
	};

	struct variable4 saver_variables[] = {
		{SAVER_NUMBER,         ASN_INTEGER,   RONLY, var_saver_number, 1, {1}},
		{SAVER_INDEX,          ASN_INTEGER,   RONLY, var_saver_entry,  3, {2, 1, 1}},
		{SAVER_NAMESPACE,      ASN_OCTET_STR, RONLY, var_saver_entry,  3, {2, 1, 2}},
		{SAVER_ADDR,           ASN_OCTET_STR, RONLY, var_saver_entry,  3, {2, 1, 3}},
		{SAVER_SCORE,          ASN_INTEGER,   RONLY, var_saver_entry,  3, {2, 1, 4}},

		{SAVER_REQ_PUSH,       ASN_COUNTER,   RONLY, var_saver_entry,  4, {2, 1, 5, 1}},
		{SAVER_REQ_STATUS,     ASN_COUNTER,   RONLY, var_saver_entry,  4, {2, 1, 5, 2}},
		{SAVER_WORKERS_BYTES,  ASN_COUNTER,   RONLY, var_saver_entry,  4, {2, 1, 5, 3}},
		{SAVER_WORKERS_OK,     ASN_COUNTER,   RONLY, var_saver_entry,  4, {2, 1, 5, 4}},
		{SAVER_WORKERS_FAILED, ASN_COUNTER,   RONLY, var_saver_entry,  4, {2, 1, 5, 5}}
	};

	struct variable4 tsmx_variables[] = {
		{TSMX_NUMBER,         ASN_INTEGER,   RONLY, var_tsmx_number, 1, {1}},
		{TSMX_INDEX,          ASN_INTEGER,   RONLY, var_tsmx_entry,  3, {2, 1, 1}},
		{TSMX_NAMESPACE,      ASN_OCTET_STR, RONLY, var_tsmx_entry,  3, {2, 1, 2}},
		{TSMX_ADDR,           ASN_OCTET_STR, RONLY, var_tsmx_entry,  3, {2, 1, 3}},
		{TSMX_SCORE,          ASN_INTEGER,   RONLY, var_tsmx_entry,  3, {2, 1, 4}},

		{TSMX_IDLE_DB,        ASN_COUNTER,   RONLY, var_tsmx_entry,  4, {2, 1, 5, 1}},
		{TSMX_IDLE_LOG,       ASN_COUNTER,   RONLY, var_tsmx_entry,  4, {2, 1, 5, 2}},
		{TSMX_IDLE_STG,       ASN_COUNTER,   RONLY, var_tsmx_entry,  4, {2, 1, 5, 3}}
	};

	struct variable4 solr_variables[] = {
		{SOLR_NUMBER,         ASN_INTEGER,   RONLY, var_solr_number, 1, {1}},
		{SOLR_INDEX,          ASN_INTEGER,   RONLY, var_solr_entry,  3, {2, 1, 1}},
		{SOLR_NAMESPACE,      ASN_OCTET_STR, RONLY, var_solr_entry,  3, {2, 1, 2}},
		{SOLR_ADDR,           ASN_OCTET_STR, RONLY, var_solr_entry,  3, {2, 1, 3}},
		{SOLR_SCORE,          ASN_INTEGER,   RONLY, var_solr_entry,  3, {2, 1, 4}},

		{SOLR_REQ_UPDATE,     ASN_GAUGE,     RONLY, var_solr_entry,  4, {2, 1, 5, 1}},
		{SOLR_REQ_SEARCH,     ASN_GAUGE,     RONLY, var_solr_entry,  4, {2, 1, 5, 2}},
		{SOLR_TIME_SEARCH,    ASN_GAUGE,     RONLY, var_solr_entry,  4, {2, 1, 5, 3}},
		{SOLR_TIME_UPDATE,    ASN_GAUGE,     RONLY, var_solr_entry,  4, {2, 1, 5, 4}},
		{SOLR_COMMITS,        ASN_COUNTER,   RONLY, var_solr_entry,  4, {2, 1, 5, 5}}
	};

	struct variable4 rplx_variables[] = {
		{RPLX_NUMBER,	      ASN_INTEGER,   RONLY, var_rplx_number, 1, {1}},
		{RPLX_INDEX,	      ASN_INTEGER,   RONLY, var_rplx_entry,  3, {2, 1, 1}},
		{RPLX_NAMESPACE,      ASN_OCTET_STR, RONLY, var_rplx_entry,  3, {2, 1, 2}},
		{RPLX_ADDR,	      ASN_OCTET_STR, RONLY, var_rplx_entry,  3, {2, 1, 3}},
		{RPLX_SCORE,	      ASN_INTEGER,   RONLY, var_rplx_entry,  3, {2, 1, 4}},
		{RPLX_NB_THREAD,      ASN_GAUGE,     RONLY, var_rplx_entry,  3, {2, 1, 5}},

		{RPLX_WORKER_CUR,     ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 6, 1}},
		{RPLX_WORKER_IDLE,    ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 6, 2}},
		{RPLX_WORKER_MAX,     ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 6, 3}},
		{RPLX_WORKER_QUEUE,   ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 6, 4}},

		{RPLX_REQ_PUSH,	      ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 7, 1}},
		{RPLX_REQ_STATUS,     ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 7, 2}},
		{RPLX_REQ_TOTAL,      ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 7, 3}},

		{RPLX_TIME_PUSH,      ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 8, 1}},
		{RPLX_TIME_STATUS,    ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 8, 2}},
		{RPLX_TIME_TOTAL,     ASN_COUNTER,   RONLY, var_rplx_entry,  4, {2, 1, 8, 3}}
	};

	struct variable4 evt_variables[] = {
		{EVT_NUMBER,          ASN_INTEGER,   RONLY, var_evt_number, 1, {1}},
		{EVT_NAMESPACE,       ASN_OCTET_STR, RONLY, var_evt_entry,  2, {2, 1}},

		{EVT_INCOMING_NB,     ASN_COUNTER,   RONLY, var_evt_entry,  2, {3, 1}},
		{EVT_INCOMING_OLDEST, ASN_INTEGER,   RONLY, var_evt_entry,  2, {3, 2}},
		{EVT_INCOMING_AGE,    ASN_INTEGER,   RONLY, var_evt_entry,  2, {3, 3}},

		{EVT_PENDING_NB,      ASN_COUNTER,   RONLY, var_evt_entry,  2, {4, 1}},
		{EVT_PENDING_OLDEST,  ASN_INTEGER,   RONLY, var_evt_entry,  2, {4, 2}},
		{EVT_PENDING_AGE,     ASN_INTEGER,   RONLY, var_evt_entry,  2, {4, 3}},
	};

	struct variable4 csc_variables[] = {
		{CSC_NUMBER,          ASN_INTEGER,   RONLY, var_csc_number, 1, {1}},
		{CSC_INDEX,	      ASN_INTEGER,   RONLY, var_csc_entry,  3, {2, 1, 1}},
		{CSC_NAMESPACE,       ASN_OCTET_STR, RONLY, var_csc_entry,  3, {2, 1, 2}},
		{CSC_ADDR,	      ASN_OCTET_STR, RONLY, var_csc_entry,  3, {2, 1, 3}},
		{CSC_SCORE,	      ASN_INTEGER,   RONLY, var_csc_entry,  3, {2, 1, 4}},
		{CSC_NB_THREAD,       ASN_GAUGE,     RONLY, var_csc_entry,  3, {2, 1, 5}},
		{CSC_NB_RAWX,         ASN_GAUGE,     RONLY, var_csc_entry,  3, {2, 1, 6}},
		{CSC_NB_RAWX_ONLINE,  ASN_GAUGE,     RONLY, var_csc_entry,  3, {2, 1, 7}},
	};

	oid meta2_variables_oid[] = { 1, 3, 6, 1, 4, 1, 3629, 66, 2 };
	oid rawx_variables_oid[] =  { 1, 3, 6, 1, 4, 1, 3629, 66, 3 };
	oid saver_variables_oid[] = { 1, 3, 6, 1, 4, 1, 3629, 66, 4 };
	oid tsmx_variables_oid[] =  { 1, 3, 6, 1, 4, 1, 3629, 66, 5 };
	oid solr_variables_oid[] =  { 1, 3, 6, 1, 4, 1, 3629, 66, 6 };
	oid rplx_variables_oid[] =  { 1, 3, 6, 1, 4, 1, 3629, 66, 7 };
	oid evt_variables_oid[] =   { 1, 3, 6, 1, 4, 1, 3629, 66, 8 };
	oid csc_variables_oid[] =   { 1, 3, 6, 1, 4, 1, 3629, 66, 9 };

	REGISTER_MIB("grid/meta2", meta2_variables, variable4, meta2_variables_oid);
	REGISTER_MIB("grid/rawx",  rawx_variables,  variable4, rawx_variables_oid);
	REGISTER_MIB("grid/saver", saver_variables, variable4, saver_variables_oid);
	REGISTER_MIB("grid/tsmx",  tsmx_variables,  variable4, tsmx_variables_oid);
	REGISTER_MIB("grid/solr",  solr_variables,  variable4, solr_variables_oid);
	REGISTER_MIB("grid/rplx",  rplx_variables,  variable4, rplx_variables_oid);
	REGISTER_MIB("grid/evt",   evt_variables,   variable4, evt_variables_oid);
	REGISTER_MIB("grid/conscience",  csc_variables,  variable4, csc_variables_oid);
}

static void
zero_local_services(void)
{
	int i;

	/* Free previous data */
	meta2_count = meta2_max_index = 0;
	rawx_count = rawx_max_index = 0;
	saver_count = saver_max_index = 0;
	tsmx_count = tsmx_max_index = 0;
	solr_count = solr_max_index = 0;
	rplx_count = rplx_max_index = 0;
	for (i=0; i<MAX_SRV ;i++) {
		if (saver_snmp_data[i])
			g_free(saver_snmp_data[i]);
		if (rawx_snmp_data[i])
			g_free(rawx_snmp_data[i]);
		if (meta2_snmp_data[i])
			g_free(meta2_snmp_data[i]);
		if (tsmx_snmp_data[i])
			g_free(tsmx_snmp_data[i]);
		if (solr_snmp_data[i])
			g_free(solr_snmp_data[i]);
		if (rplx_snmp_data[i])
			g_free(rplx_snmp_data[i]);
	}
	bzero(saver_snmp_data, sizeof(saver_snmp_data));
	bzero(rawx_snmp_data, sizeof(rawx_snmp_data));
	bzero(meta2_snmp_data, sizeof(meta2_snmp_data));
	bzero(tsmx_snmp_data, sizeof(tsmx_snmp_data));
	bzero(solr_snmp_data, sizeof(solr_snmp_data));
	bzero(rplx_snmp_data, sizeof(rplx_snmp_data));
}

/* Because the array stores services at their service-index and not
 * in subsequent array slots, we fill the blanks with zeroed stats */
static void
ensure_service_stats(void)
{
	int i;

	for (i = 0; i <= saver_max_index; i++)
		if (saver_snmp_data[i] == NULL)
			saver_snmp_data[i] = g_try_new0(struct saver_snmp_data, 1);
	for (i = 0; i <= meta2_max_index; i++)
		if (meta2_snmp_data[i] == NULL)
			meta2_snmp_data[i] = g_try_new0(struct meta2_snmp_data, 1);
	for (i = 0; i <= rawx_max_index; i++)
		if (rawx_snmp_data[i] == NULL)
			rawx_snmp_data[i] = g_try_new0(struct rawx_snmp_data, 1);
	for (i = 0; i <= tsmx_max_index; i++)
		if (tsmx_snmp_data[i] == NULL)
			tsmx_snmp_data[i] = g_try_new0(struct tsmx_snmp_data, 1);
	for (i = 0; i <= solr_max_index; i++)
		if (solr_snmp_data[i] == NULL)
			solr_snmp_data[i] = g_try_new0(struct solr_snmp_data, 1);
	for (i = 0; i <= rplx_max_index; i++)
		if (rplx_snmp_data[i] == NULL)
			rplx_snmp_data[i] = g_try_new0(struct rplx_snmp_data, 1);
}

static void
fill_local_services(GSList *services)
{
	GSList *service;
	struct service_info_s *si = NULL;

	if (!services)
		return;

	for (service = services; service && service->data; service = service->next) {
		gchar str_addr[256];

		si = (struct service_info_s*) service->data;
	
		if (0 == g_ascii_strcasecmp(si->type, "rawx")) {
			manage_rawx(si);
			continue;
		}
		if (0 == g_ascii_strcasecmp(si->type,"meta2")) {
			manage_meta2(si);
			continue;
		}
		if (0 == g_ascii_strcasecmp(si->type,"saver")) {
			manage_saver(si);
			continue;
		}
		if (0 == g_ascii_strcasecmp(si->type, "tsmx")) {
			manage_tsmx(si);
			continue;
		}
		if (0 == g_ascii_strcasecmp(si->type, "solr")) {
			manage_solr(si);
			continue;
		}
		if (0 == g_ascii_strcasecmp(si->type, "replicator")) {
			manage_rplx(si);
			continue;
		}

		addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
		DEBUGMSGTL(("grid", "local service not managed %s/%s/%s\n", si->ns_name, si->type, str_addr));
	}
}

static void
reload_local_services(void)
{
	static time_t last_update = 0;
	time_t now;
	GSList *services;
	GError *error = NULL;

	/*check we didn't reload the data recently*/
	now = time(0);
	if (now <= last_update+29)
		return;
	last_update = now;

	/*gathers all the services*/
	services = list_local_services(&error);
	if (services == NULL) {
		if (error) {
			DEBUGMSGTL(("grid", "Failed to list grid services : %s\n", error->message));
			g_clear_error(&error);
		}
		return;
	}

	zero_local_services();
	fill_local_services(services);
	ensure_service_stats();

	g_slist_foreach(services, service_info_gclean, NULL);
	g_slist_free(services);
}

static void
reload_events(void)
{
	static time_t last_update = 0;
	time_t now;
	GSList *ns = NULL, *l = NULL;
	int i;

	/*check we didn't reload the data recently*/
	now = time(0);
	if (now <= last_update+29)
		return;
	last_update = now;

	/* zero current stats */
	evt_count = evt_max_index = 0;
	for (i=0; i<MAX_SRV ;i++) {
		if (evt_snmp_data[i])
			g_free(evt_snmp_data[i]);
	}
	bzero(evt_snmp_data, sizeof(evt_snmp_data));

	/* List ns in spool dir */
	ns = list_ns(evt_spool_dir);
	if (ns)
		for (l = ns; l; l = l->next)
			if (l->data)
				manage_evt(l->data);

	/* Ensure stats */
	for (i = 0; i <= evt_max_index; i++)
		if (evt_snmp_data[i] == NULL)
			evt_snmp_data[i] = g_try_new0(struct evt_snmp_data, 1);

	/* Clean */
	g_slist_foreach(ns, g_free1, NULL);
	g_slist_free(ns);
}

static void
reload_conscience(void)
{
	static time_t last_update = 0;
	time_t now;
	GSList *l = NULL;
	int i;

	/*check we didn't reload the data recently*/
	now = time(0);
	if (now <= last_update+29)
		return;
	last_update = now;

	/* zero current stats */
	csc_count = csc_max_index = 0;
	for (i=0; i<MAX_SRV ;i++) {
		if (csc_snmp_data[i])
			g_free(csc_snmp_data[i]);
	}
	bzero(csc_snmp_data, sizeof(csc_snmp_data));

	if (csc_ns_list)
		for (l = csc_ns_list; l; l = l->next)
			if (l->data)
				manage_csc(l->data);

	/* Ensure stats */
	for (i = 0; i <= csc_max_index; i++)
		if (csc_snmp_data[i] == NULL)
			csc_snmp_data[i] = g_try_new0(struct csc_snmp_data, 1);
}

static int
count_meta2(void)
{
	reload_local_services();
	return meta2_count;
}

static int
count_rawx(void)
{
	reload_local_services();
	return rawx_count;
}

static int
count_saver(void)
{
	reload_local_services();
	return saver_count;
}

static int
count_tsmx(void)
{
	reload_local_services();
	return tsmx_count;
}

static int
count_solr(void)
{
	reload_local_services();
	return solr_count;
}

static int
count_rplx(void)
{
	reload_local_services();
	return rplx_count;
}

static int
count_evt(void)
{
	reload_events();
	return evt_count;
}

static int
count_csc(void)
{
	reload_conscience();
	return csc_count;
}

static guint32
get_uint32_tag_value(struct service_info_s *si, const gchar *n, guint32 def)
{
	guint32 result;
	struct service_tag_s *tag;
	if (!si->tags)
		return def;
	tag = service_info_get_tag(si->tags, n);
	if (!tag)
		return def;
	switch (tag->type) {
		case STVT_I64:
			return tag->value.i;
		case STVT_REAL:
			result = tag->value.r;
			return result;
		case STVT_BOOL:
			result = tag->value.b ? 1LU : 0LU;
			return result;
		default:
			return def;
	}
}

/* XXX absolutely thread-unsafe, but no problem, the SNMPd process has
 * only one thread XXX */
static const gchar*
get_string_tag_value(struct service_info_s *si, const gchar *n, const gchar *def)
{
	static gchar result[64];
	struct service_tag_s *tag;
	
	if (!si->tags)
		return def;
	tag = service_info_get_tag(si->tags, n);
	if (!tag)
		return def;
	switch (tag->type) {
		case STVT_I64:
			g_snprintf(result, sizeof(result), "%"G_GINT64_FORMAT, tag->value.i);
			return result;
		case STVT_REAL:
			g_snprintf(result, sizeof(result), "%f", tag->value.r);
			return result;
		case STVT_BOOL:
			return  tag->value.b ? "1" : "0";
		case STVT_STR:
			return tag->value.s;
		case STVT_BUF:
			return tag->value.buf;
		default:
			return def;
	}
}

static gdouble
get_double_value(GHashTable *ht, const gchar *k, gdouble default_value)
{
	gdouble *pRes;
	
	if (!ht || !k)
		return default_value;
	
	pRes = (gdouble*) g_hash_table_lookup( ht, k );
	if (!pRes) {
		DEBUGMSGTL(("grid", "[%s] not found in statistics\n", k));
		return default_value;
	}

	return *pRes;
}

static void
manage_meta2(struct service_info_s *si)
{
	struct meta2_snmp_data snmp_data;
	GHashTable *meta2_stats = NULL;
	GError *error = NULL;
	struct grid_service_data index_data;

	memset(&snmp_data, 0, sizeof(struct meta2_snmp_data));
	memset(&index_data, 0, sizeof(struct grid_service_data));
	
	/*set meta2 stats from the service_info*/
	addr_info_to_string(&(si->addr), snmp_data.addr, sizeof(snmp_data.addr));
	snprintf(index_data.desc, MAX_DESC_LENGTH, "%s|%s", si->ns_name, snmp_data.addr);
	strncpy(snmp_data.namespace, si->ns_name, LIMIT_LENGTH_NSNAME);
	snmp_data.score = si->score.value;

	/*get the index from file*/
	if (!get_idx_of_service("meta2", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retieve index of meta2 [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return ;
	}

	/* Get stats for this meta2 */
	meta2_stats = gridd_stats_remote(&(si->addr), SOCK_TIMEOUT, &error, "*");
	if (!meta2_stats) {
		DEBUGMSGTL(("grid", "Failed to stat meta2 [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.req_total = get_double_value(meta2_stats, META2_STAT_REQ_TOTAL, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_TOTAL_V2, 0.0);
		snmp_data.req_create = get_double_value(meta2_stats, META2_STAT_REQ_CREATE, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CREATE_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CREATE_V2, 0.0);
		snmp_data.req_list = get_double_value(meta2_stats, META2_STAT_REQ_LIST, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_LIST_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_LIST_V2, 0.0);
		snmp_data.req_close = get_double_value(meta2_stats, META2_STAT_REQ_CLOSE, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CLOSE_V2, 0.0);
		snmp_data.req_destroy = get_double_value(meta2_stats, META2_STAT_REQ_DESTROY, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_DESTROY_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_DESTROY_V2, 0.0);
		snmp_data.req_open = get_double_value(meta2_stats, META2_STAT_REQ_OPEN, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_OPEN_V2, 0.0);
		snmp_data.req_failures = get_double_value(meta2_stats, META2_STAT_REQ_FAIL, 0.0);
		snmp_data.req_content_retrieve = get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_RET, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_RET_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_RET_V2, 0.0);
		snmp_data.req_content_remove = get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_RM, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_RM_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_RM_V2, 0.0);
		snmp_data.req_content_add = get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_ADD, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_ADD_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_ADD_V2, 0.0);
		snmp_data.req_content_append = get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_APPEND, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_APPEND_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_APPEND_V2, 0.0);
		snmp_data.req_content_commit = get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_COMMIT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CONTENT_COMMIT_V1, 0.0);
		snmp_data.req_chunk_commit = get_double_value(meta2_stats, META2_STAT_REQ_CHUNK_COMMIT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_CHUNK_COMMIT_V1, 0.0);
		snmp_data.req_rplcontent = get_double_value(meta2_stats, META2_STAT_REQ_RPLCONTENT, 0.0);
		snmp_data.req_statcontent = get_double_value(meta2_stats, META2_STAT_REQ_STATCONTENT, 0.0);

		snmp_data.time_create = get_double_value(meta2_stats, META2_STAT_TIME_CREATE, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CREATE_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CREATE_V2, 0.0);
		snmp_data.time_content_retrieve =
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_RET, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_RET_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_RET_V2, 0.0);
		snmp_data.time_list = get_double_value(meta2_stats, META2_STAT_TIME_LIST, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_LIST_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_LIST_V2, 0.0);
		snmp_data.time_close = get_double_value(meta2_stats, META2_STAT_TIME_CLOSE, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CLOSE_V1, 0.0);
		snmp_data.time_destroy = get_double_value(meta2_stats, META2_STAT_TIME_DESTROY, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_DESTROY_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_DESTROY_V2, 0.0);
		snmp_data.time_content_remove = get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_RM, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_RM_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_RM_V2, 0.0);
		snmp_data.time_open = get_double_value(meta2_stats, META2_STAT_TIME_OPEN, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_OPEN_V1, 0.0);
		snmp_data.time_content_add = get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_ADD, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_ADD_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_ADD_V2, 0.0);
		snmp_data.time_content_append =
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_APPEND, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_APPEND_V1, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_APPEND_V2, 0.0);
		snmp_data.time_content_commit = get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_CI, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CONTENT_CI_V1, 0.0);
		snmp_data.time_chunk_commit = get_double_value(meta2_stats, META2_STAT_TIME_CHUNK_CI, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_CHUNK_CI_V1, 0.0);
		snmp_data.time_rplcontent = get_double_value(meta2_stats, META2_STAT_TIME_RPLCONTENT, 0.0);
		snmp_data.time_statcontent = get_double_value(meta2_stats, META2_STAT_TIME_STATCONTENT, 0.0);

		snmp_data.req_maintenance_getcontent =
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_GETCONTENT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_GETCONTENT_V1, 0.0);
		snmp_data.req_maintenance_getchunks =
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_GETCHUNK, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_GETCHUNK_V1, 0.0);
		snmp_data.req_maintenance_setcontent =
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_SETCONTENT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_SETCONTENT_V1, 0.0);
		snmp_data.req_maintenance_setchunks =
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_SETCHUNK, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_SETCHUNK_V1, 0.0);
		snmp_data.req_maintenance_delcontent =
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_DELCONTENT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_DELCONTENT_V1, 0.0);
		snmp_data.req_maintenance_delchunks =
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_DELCHUNK, 0.0) +
			get_double_value(meta2_stats, META2_STAT_REQ_RAW_DELCHUNK_V1, 0.0);
		snmp_data.req_maintenance_other = get_double_value(meta2_stats, META2_STAT_REQ_RAW_OTHER, 0.0);

		snmp_data.time_maintenance_getcontent =
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_GETCONTENT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_GETCONTENT_V1, 0.0);
		snmp_data.time_maintenance_getchunks =
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_GETCHUNK, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_GETCHUNK_V1, 0.0);
		snmp_data.time_maintenance_setcontent =
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_SETCONTENT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_SETCONTENT_V1, 0.0);
		snmp_data.time_maintenance_setchunks =
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_SETCHUNK, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_SETCHUNK_V1, 0.0);
		snmp_data.time_maintenance_delcontent =
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_DELCONTENT, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_DELCONTENT_V1, 0.0);
		snmp_data.time_maintenance_delchunks =
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_DELCHUNK, 0.0) +
			get_double_value(meta2_stats, META2_STAT_TIME_RAW_DELCHUNK_V1, 0.0);
		snmp_data.time_maintenance_other = get_double_value(meta2_stats, META2_STAT_TIME_RAW_OTHER, 0.0);

		snmp_data.req_prop_set_content =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_SET_CONTENT, 0.0);
		snmp_data.req_prop_set_container =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_SET_CONTAINER, 0.0);
		snmp_data.req_prop_get_content =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_GET_CONTENT, 0.0);
		snmp_data.req_prop_get_container =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_GET_CONTAINER, 0.0);
		snmp_data.req_prop_rm_content =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_RM_CONTENT, 0.0);
		snmp_data.req_prop_rm_container	=
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_RM_CONTAINER, 0.0);
		snmp_data.req_prop_rpl_set_container =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_RPL_SET_CONTAINER, 0.0);
		snmp_data.req_prop_rpl_rm_container =
			get_double_value(meta2_stats, META2_STAT_REQ_PROP_RPL_RM_CONTAINER, 0.0);

		snmp_data.time_prop_set_content	=
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_SET_CONTENT, 0.0);
		snmp_data.time_prop_set_container =
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_SET_CONTAINER, 0.0);
		snmp_data.time_prop_get_content	=
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_GET_CONTENT, 0.0);
		snmp_data.time_prop_get_container =
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_GET_CONTAINER, 0.0);
		snmp_data.time_prop_rm_content =
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_RM_CONTENT, 0.0);
		snmp_data.time_prop_rm_container =
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_RM_CONTAINER, 0.0);
		snmp_data.time_prop_rpl_set_container =
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_RPL_SET_CONTAINER, 0.0);
		snmp_data.time_prop_rpl_rm_container =
			get_double_value(meta2_stats, META2_STAT_TIME_PROP_RPL_RM_CONTAINER, 0.0);

		snmp_data.nb_thread = get_double_value(meta2_stats, META2_STAT_NB_THREAD, 0.0) +
			get_double_value(meta2_stats, META2_STAT_NB_THREAD_V2, 0.0);

		g_hash_table_destroy(meta2_stats);
	}

	/*then save the current information*/
	if (meta2_snmp_data[index_data.idx])
		g_free(meta2_snmp_data[index_data.idx]);
	meta2_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct meta2_snmp_data));
	meta2_max_index = MAX(meta2_max_index, index_data.idx);
	meta2_count ++;
}

static void
manage_saver(struct service_info_s *si)
{
	struct saver_snmp_data snmp_data;
	GHashTable *saver_stats = NULL;
	GError *error = NULL;
	struct grid_service_data index_data;

	bzero(&snmp_data, sizeof(struct saver_snmp_data));
	bzero(&index_data, sizeof(struct grid_service_data));
	
	/*set saver stats from the service_info*/
	snmp_data.score = si->score.value;
	addr_info_to_string(&(si->addr), snmp_data.addr, sizeof(snmp_data.addr));
	g_strlcpy(snmp_data.namespace, si->ns_name, LIMIT_LENGTH_NSNAME);
	g_snprintf(index_data.desc, MAX_DESC_LENGTH, "%s|%s", snmp_data.namespace, snmp_data.addr);

	/*get the index from file*/
	if (!get_idx_of_service("saver", &index_data, &error)) {
		DEBUGMSGTL(("grid", "%s no index for [%s] : %s\n", __FUNCTION__, index_data.desc, error->message));
		g_clear_error(&error);
		return ;
	}

	/* Get stats for this saver */
	saver_stats = gridd_stats_remote(&(si->addr), SOCK_TIMEOUT, &error, "*");
	if (!saver_stats) {
		DEBUGMSGTL(("grid", "%s gridc_stat failed for [%s] : %s\n", __FUNCTION__, index_data.desc, error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.req_status =    get_double_value(saver_stats, SAVER_STAT_REQ_STATUS, 0.0);
		snmp_data.req_push =      get_double_value(saver_stats, SAVER_STAT_REQ_PUSH, 0.0);
		snmp_data.workers_bytes = get_double_value(saver_stats, SAVER_STAT_BYTES, 0.0);
		snmp_data.workers_ok =    get_double_value(saver_stats, SAVER_STAT_WORKER_OK, 0.0);
		snmp_data.workers_ko =    get_double_value(saver_stats, SAVER_STAT_WORKER_KO, 0.0);
		g_hash_table_destroy(saver_stats);
	}

	/*then save the current information*/
	if (saver_snmp_data[index_data.idx])
		g_free(saver_snmp_data[index_data.idx]);
	saver_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct saver_snmp_data));
	saver_max_index = MAX(saver_max_index, index_data.idx);
	saver_count ++;
}

static void
manage_rawx(struct service_info_s *si)
{
	struct rawx_snmp_data snmp_data;
	struct grid_service_data index_data;
	rawx_session_t *session;
	GError *error = NULL;
	GHashTable *rawx_stats;

	memset(&index_data, 0, sizeof(struct grid_service_data));
	memset(&snmp_data, 0, sizeof(struct rawx_snmp_data));

	/* Set rawx stat from the service definition*/
	strncpy(snmp_data.namespace, si->ns_name, LIMIT_LENGTH_NSNAME);
	addr_info_to_string(&(si->addr), snmp_data.addr, sizeof(snmp_data.addr));
	strncpy(snmp_data.volume, get_string_tag_value(si, "tag.vol", snmp_data.addr), LIMIT_LENGTH_VOLUMENAME);
	snmp_data.score = si->score.value;
	snmp_data.free_chunk = get_uint32_tag_value(si, "stat.space", 1);
	snmp_data.io_idle = get_uint32_tag_value(si, "stat.io", 1);

	/* Get index from file */
	snprintf(index_data.desc, MAX_DESC_LENGTH, "%s|%s", si->ns_name, snmp_data.addr);
	if (!get_idx_of_service("rawx", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retieve index of rawx [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return;
	}

	/*contact the rawx itself to collect the stats*/
	session = rawx_client_create_session(&(si->addr), NULL);
	rawx_client_session_set_timeout(session, SOCK_TIMEOUT, SOCK_TIMEOUT);
	rawx_stats = session ? rawx_client_get_statistics(session, RAWX_STAT_URL, &error) : NULL;
	rawx_client_free_session(session);
	if (!rawx_stats) {
		DEBUGMSGTL(("grid", "Failed to retieve RAWX internal stats : %s\n", error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.req_all =   get_double_value( rawx_stats, RAWX_STATKEY_REQ_ALL, 0.0);
		snmp_data.req_get =   get_double_value( rawx_stats, RAWX_STATKEY_REQ_GET, 0.0);
		snmp_data.req_put =   get_double_value( rawx_stats, RAWX_STATKEY_REQ_PUT, 0.0);
		snmp_data.req_del =   get_double_value( rawx_stats, RAWX_STATKEY_REQ_DEL, 0.0);
		snmp_data.req_info =  get_double_value( rawx_stats, RAWX_STATKEY_REQ_INFO, 0.0);
		snmp_data.req_stat =  get_double_value( rawx_stats, RAWX_STATKEY_REQ_STAT, 0.0);
		snmp_data.req_raw =   get_double_value( rawx_stats, RAWX_STATKEY_REQ_RAW, 0.0);
		snmp_data.req_other = get_double_value( rawx_stats, RAWX_STATKEY_REQ_OTHER, 0.0);

		snmp_data.rep_2xx =   get_double_value( rawx_stats, RAWX_STATKEY_REP_2XX, 0.0);
		snmp_data.rep_4xx =   get_double_value( rawx_stats, RAWX_STATKEY_REP_4XX, 0.0);
		snmp_data.rep_5xx =   get_double_value( rawx_stats, RAWX_STATKEY_REP_5XX, 0.0);
		snmp_data.rep_403 =   get_double_value( rawx_stats, RAWX_STATKEY_REP_403, 0.0);
		snmp_data.rep_404 =   get_double_value( rawx_stats, RAWX_STATKEY_REP_404, 0.0);
		snmp_data.rep_other = get_double_value( rawx_stats, RAWX_STATKEY_REP_OTHER, 0.0);

		snmp_data.bytes_read = get_double_value( rawx_stats, RAWX_STATKEY_BYTES_READ, 0.0);
		snmp_data.bytes_written = get_double_value( rawx_stats, RAWX_STATKEY_BYTES_WRITTEN, 0.0);

		g_hash_table_destroy( rawx_stats );
	}

	/*then save the current information*/
	if (rawx_snmp_data[index_data.idx])
		g_free(rawx_snmp_data[index_data.idx]);
	rawx_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct rawx_snmp_data));
	rawx_max_index = MAX(rawx_max_index, index_data.idx);
	rawx_count ++;
}

static void
manage_tsmx(struct service_info_s *si)
{
	struct tsmx_snmp_data snmp_data;
	struct grid_service_data index_data;
	rawx_session_t *session;
	GError *error = NULL;
	GHashTable *tsmx_stats;

	DEBUGMSGTL(("grid", "%s new service\n", __FUNCTION__));
	memset(&index_data, 0, sizeof(struct grid_service_data));
	memset(&snmp_data, 0, sizeof(struct tsmx_snmp_data));

	/* Set tsmx stat from the service definition*/
	g_strlcpy(snmp_data.namespace, si->ns_name, sizeof(snmp_data.namespace)-1);
	addr_info_to_string(&(si->addr), snmp_data.addr, sizeof(snmp_data.addr));
	snmp_data.score = si->score.value;
	snmp_data.idle_db  =  get_uint32_tag_value(si, "stat.tsm_idle_db", 0);
	snmp_data.idle_log =  get_uint32_tag_value(si, "stat.tsm_idle_log", 0);
	snmp_data.idle_stg =  get_uint32_tag_value(si, "stat.tsm_idle_stg", 0);

	/* Get index from file */
	g_snprintf(index_data.desc, MAX_DESC_LENGTH, "%s|%s", snmp_data.namespace, snmp_data.addr);
	if (!get_idx_of_service("tsmx", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retieve index of tsmx [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return;
	}

	/*contact the tsmx itself to collect the stats*/
	session = rawx_client_create_session(&(si->addr), NULL);
	rawx_client_session_set_timeout(session, SOCK_TIMEOUT, SOCK_TIMEOUT);
	tsmx_stats = session ? rawx_client_get_statistics(session, TSMX_STAT_URL, &error) : NULL;
	rawx_client_free_session(session);
	if (!tsmx_stats) {
		DEBUGMSGTL(("grid", "Failed to retieve TSMX internal stats : %s\n", error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.req_put =   get_double_value(tsmx_stats, TSMX_STATKEY_REQ_PUT, 0.0);
		snmp_data.req_get =   get_double_value(tsmx_stats, TSMX_STATKEY_REQ_GET, 0.0);
		snmp_data.req_del =   get_double_value(tsmx_stats, TSMX_STATKEY_REQ_DEL, 0.0);
		snmp_data.failed =    get_double_value(tsmx_stats, TSMX_STATKEY_FAILED, 0.0);
		snmp_data.bytes_in =  get_double_value(tsmx_stats, TSMX_STATKEY_BYTES_IN, 0.0);
		snmp_data.bytes_out = get_double_value(tsmx_stats, TSMX_STATKEY_BYTES_OUT, 0.0);

		g_hash_table_destroy( tsmx_stats );
	}

	/*then save the current information*/
	if (tsmx_snmp_data[index_data.idx])
		g_free(tsmx_snmp_data[index_data.idx]);
	tsmx_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct tsmx_snmp_data));
	tsmx_max_index = MAX(tsmx_max_index, index_data.idx);
	tsmx_count ++;
}

static void
manage_solr(struct service_info_s *si)
{
	struct solr_snmp_data snmp_data;
	struct grid_service_data index_data;
	rawx_session_t *session;
	GError *error = NULL;
	GHashTable *solr_stats;

	DEBUGMSGTL(("grid", "%s new service\n", __FUNCTION__));
	memset(&index_data, 0, sizeof(struct grid_service_data));
	memset(&snmp_data, 0, sizeof(struct solr_snmp_data));

	/* Set solr stat from the service definition*/
	g_strlcpy(snmp_data.namespace, si->ns_name, sizeof(snmp_data.namespace)-1);
	addr_info_to_string(&(si->addr), snmp_data.addr, sizeof(snmp_data.addr));
	snmp_data.score = si->score.value;

	/* Get index from file */
	g_snprintf(index_data.desc, MAX_DESC_LENGTH, "%s|%s", snmp_data.namespace, snmp_data.addr);
	if (!get_idx_of_service("solr", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retieve index of solr [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return;
	}

	/*contact the solr itself to collect the stats*/
	session = rawx_client_create_session(&(si->addr), NULL);
	rawx_client_session_set_timeout(session, SOCK_TIMEOUT, SOCK_TIMEOUT);
	solr_stats = session ? rawx_client_get_statistics(session, SOLR_STAT_URL, &error) : NULL;
	rawx_client_free_session(session);
	if (!solr_stats) {
		DEBUGMSGTL(("grid", "Failed to retrieve SOLR internal stats : %s\n", error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.req_search =   get_double_value(solr_stats, SOLR_STATKEY_REQ_SEARCH, 0.0);
		snmp_data.req_update =   get_double_value(solr_stats, SOLR_STATKEY_REQ_UPDATE, 0.0);
		snmp_data.time_search =  get_double_value(solr_stats, SOLR_STATKEY_TIME_SEARCH, 0.0);
		snmp_data.time_update =  get_double_value(solr_stats, SOLR_STATKEY_TIME_UPDATE, 0.0);
		snmp_data.commits =      get_double_value(solr_stats, SOLR_STATKEY_COMMITS, 0.0);

		g_hash_table_destroy( solr_stats );
	}

	/*then save the current information*/
	if (solr_snmp_data[index_data.idx])
		g_free(solr_snmp_data[index_data.idx]);
	solr_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct solr_snmp_data));
	solr_max_index = MAX(solr_max_index, index_data.idx);
	solr_count ++;
}

static void
manage_rplx(struct service_info_s *si)
{
	struct rplx_snmp_data snmp_data;
	GHashTable *rplx_stats = NULL;
	GError *error = NULL;
	struct grid_service_data index_data;

	memset(&snmp_data, 0, sizeof(struct rplx_snmp_data));
	memset(&index_data, 0, sizeof(struct grid_service_data));
	
	/*set rplx stats from the service_info*/
	addr_info_to_string(&(si->addr), snmp_data.addr, sizeof(snmp_data.addr));
	snprintf(index_data.desc, MAX_DESC_LENGTH, "%s|%s", si->ns_name, snmp_data.addr);
	strncpy(snmp_data.namespace, si->ns_name, LIMIT_LENGTH_NSNAME);
	snmp_data.score = si->score.value;

	/*get the index from file*/
	if (!get_idx_of_service("rplx", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retieve index of rplx [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return ;
	}

	/* Get stats for this rplx */
	rplx_stats = gridd_stats_remote(&(si->addr), SOCK_TIMEOUT, &error, "*");
	if (!rplx_stats) {
		DEBUGMSGTL(("grid", "Failed to stat rplx [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.worker_current =	get_double_value(rplx_stats, RPLX_STAT_WORKERS_CUR, 0.0);
		snmp_data.worker_idle =	 	get_double_value(rplx_stats, RPLX_STAT_WORKERS_IDLE, 0.0);
		snmp_data.worker_max =	 	get_double_value(rplx_stats, RPLX_STAT_WORKERS_MAX, 0.0);
		snmp_data.worker_queue =	get_double_value(rplx_stats, RPLX_STAT_WORKERS_QUEUE, 0.0);
		snmp_data.req_push =		get_double_value(rplx_stats, RPLX_STAT_REQ_PUSH, 0.0);
		snmp_data.req_status =		get_double_value(rplx_stats, RPLX_STAT_REQ_STATUS, 0.0);
		snmp_data.req_total =		get_double_value(rplx_stats, RPLX_STAT_REQ_TOTAL, 0.0);
	
		snmp_data.nb_thread = *(gdouble*)g_hash_table_lookup(rplx_stats, RPLX_STAT_NB_THREAD);
		g_hash_table_destroy(rplx_stats);
	}

	/*then save the current information*/
	if (rplx_snmp_data[index_data.idx])
		g_free(rplx_snmp_data[index_data.idx]);
	rplx_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct rplx_snmp_data));
	rplx_max_index = MAX(rplx_max_index, index_data.idx);
	rplx_count ++;
}

static void
manage_evt(const gchar *ns_name)
{
	struct evt_snmp_data snmp_data;
	struct grid_service_data index_data;
	spooldir_stat_t incoming_stat;
	spooldir_stat_t pending_stat;
	gchar *fullpath = NULL;
	GError *error = NULL;

	memset(&snmp_data, 0, sizeof(struct evt_snmp_data));
	memset(&index_data, 0, sizeof(struct grid_service_data));
	memset(&incoming_stat, 0, sizeof(spooldir_stat_t));
	memset(&pending_stat, 0, sizeof(spooldir_stat_t));
	
	/*set evt stats*/
	snprintf(index_data.desc, MAX_DESC_LENGTH, "%s", ns_name);
	strncpy(snmp_data.namespace, ns_name, LIMIT_LENGTH_NSNAME);

	/*get the index from file*/
	if (!get_idx_of_service("evt", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retieve index of evt [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return ;
	}

	/* Get stats for this ns evts */
	fullpath = g_strconcat(evt_spool_dir, G_DIR_SEPARATOR_S, ns_name, G_DIR_SEPARATOR_S, "incoming", NULL);
	if (stat_events(&incoming_stat, fullpath)) {
		snmp_data.incoming_nb = incoming_stat.nb_evt;
		if (incoming_stat.nb_evt > 0) {
			snmp_data.incoming_age = incoming_stat.total_age / incoming_stat.nb_evt;
			snmp_data.incoming_oldest = incoming_stat.oldest;
		}
	}
	g_free(fullpath);
	fullpath = g_strconcat(evt_spool_dir, G_DIR_SEPARATOR_S, ns_name, G_DIR_SEPARATOR_S, "pending", NULL);
	if (stat_events(&pending_stat, fullpath)) {
		snmp_data.pending_nb = pending_stat.nb_evt;
		if (pending_stat.nb_evt > 0) {
			snmp_data.pending_age = pending_stat.total_age / pending_stat.nb_evt;
			snmp_data.pending_oldest = pending_stat.oldest;
		}
	}
	g_free(fullpath);

	/*then save the current information*/
	if (evt_snmp_data[index_data.idx])
		g_free(evt_snmp_data[index_data.idx]);
	evt_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct evt_snmp_data));
	evt_max_index = MAX(evt_max_index, index_data.idx);
	evt_count ++;
}

static void
manage_csc(const gchar * ns_name)
{
	struct csc_snmp_data snmp_data;
	GHashTable *csc_stats = NULL;
	GError *error = NULL;
	struct grid_service_data index_data;
	namespace_info_t *ns_info = NULL;
	GSList *services = NULL, *l = NULL;
	addr_info_t csc_addr;

	memset(&snmp_data, 0, sizeof(struct csc_snmp_data));
	memset(&index_data, 0, sizeof(struct grid_service_data));
	memset(&csc_addr, 0, sizeof(addr_info_t));

	/* Get conscience addr from gridstorage.conf */
	ns_info = get_namespace_info(ns_name, &error);
	if (ns_info == NULL) {
		DEBUGMSGTL(("grid", "Failed to retrieve namespace info for [%s] : %s\n", ns_name, error->message));
		g_clear_error(&error);
		return;
	}
	memcpy(&csc_addr, &(ns_info->addr), sizeof(addr_info_t));
	namespace_info_free(ns_info);
	
	/*set conscience stats from the service_info*/
	addr_info_to_string(&csc_addr, snmp_data.addr, sizeof(snmp_data.addr));
	snprintf(index_data.desc, MAX_DESC_LENGTH, "%s", ns_name);
	strncpy(snmp_data.namespace, ns_name, LIMIT_LENGTH_NSNAME);

	/*get the index from file*/
	if (!get_idx_of_service("csc", &index_data, &error)) {
		DEBUGMSGTL(("grid", "Failed to retrieve index of conscience [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
		return ;
	}

	/* Get stats for this conscience */
	csc_stats = gridd_stats_remote(&csc_addr, SOCK_TIMEOUT, &error, "*");
	if (!csc_stats) {
		DEBUGMSGTL(("grid", "Failed to stat conscience [%s] : %s\n", index_data.desc, error->message));
		g_clear_error(&error);
	}
	else {
		snmp_data.nb_thread = *(gdouble*)g_hash_table_lookup(csc_stats, CSC_STAT_NB_THREAD);
		g_hash_table_destroy(csc_stats);
	}

	/* Get service stats */
	services = gcluster_get_services(&csc_addr, SOCK_TIMEOUT, NAME_SRVTYPE_RAWX, &error);
	if (services == NULL) {
		DEBUGMSGTL(("grid", "Failed to retrieve the list of RAWX in namespace [%s] : %s\n", ns_name, error->message));
		g_clear_error(&error);
	}
	for (l = services; l; l = l->next) {
		if (l->data) {
			snmp_data.nb_rawx++;
			if (((service_info_t*)l->data)->score.value > 0)
				snmp_data.nb_rawx_online++;
		}
	}
	g_slist_foreach(services, service_info_gclean, NULL);
	g_slist_free(services);

	/*then save the current information*/
	if (csc_snmp_data[index_data.idx])
		g_free(csc_snmp_data[index_data.idx]);
	csc_snmp_data[index_data.idx] = g_memdup(&snmp_data, sizeof(struct csc_snmp_data));
	csc_max_index = MAX(csc_max_index, index_data.idx);
	csc_count ++;
}


/* ------------------------------------------------------------------------- */

static inline u_char*
__get_simple(const char *func, int magic,
		struct variable * vp, oid * name, size_t * length,
		int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};

	oid_to_string(name, *length, str_oid, sizeof(str_oid));

	if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n", func, vp->magic, str_oid));
		return(NULL);
	}

	if (vp->magic == magic) {
		long_return = (long) count_meta2;
		return (u_char *) &long_return;
	}

	DEBUGMSGTL(("grid", "%s unknown sub-id magic=%d oid=%s\n", func, vp->magic, str_oid));
	return NULL;
}

u_char*
var_meta2_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, META2_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_rawx_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, RAWX_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_saver_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, SAVER_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_tsmx_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, TSMX_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_solr_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, SOLR_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_rplx_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, RPLX_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_evt_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, EVT_NUMBER, vp, name, length, exact, var_len, write_method);
}

u_char*
var_csc_number(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	return __get_simple(__FUNCTION__, CSC_NUMBER, vp, name, length, exact, var_len, write_method);
}

/* ------------------------------------------------------------------------- */

#define CASELONG(M,F) case M: long_return = snmp_data->F; return (u_char *) &long_return

u_char*
var_meta2_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct meta2_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_local_services();

	if (meta2_max_index < 0 || meta2_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, meta2_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;
	snmp_data = meta2_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
		case META2_NUMBER:
			long_return = (long) count_meta2;
			return (u_char *) &long_return;

		case META2_INDEX:
			long_return = (long) idx + 1;
			return (u_char *) &long_return;

		case META2_NAMESPACE:
			*var_len = strlen(snmp_data->namespace);
			return (u_char *) snmp_data->namespace;

		case META2_ADDR:
			*var_len = strlen(snmp_data->addr);
			return (u_char *) snmp_data->addr;

		CASELONG(META2_SCORE, score);
		CASELONG(META2_REQ_TOTAL,req_total);
		CASELONG(META2_REQ_CREATE,req_create);
		case META2_REQ_ALLGETS:
			long_return = snmp_data->req_content_retrieve
				+ snmp_data->req_maintenance_getchunks
				+ snmp_data->req_maintenance_getcontent;
			return (u_char *) &long_return;
		CASELONG(META2_REQ_LIST, req_list);
		CASELONG(META2_REQ_CLOSE, req_close);
		CASELONG(META2_REQ_DESTROY, req_destroy);
		CASELONG(META2_REQ_CONTENT_RM, req_content_remove);
		CASELONG(META2_REQ_OPEN, req_open);
		CASELONG(META2_REQ_FAIL, req_failures);
		case META2_REQ_CONTENT_ALLPUTS:
			long_return = snmp_data->req_content_add + snmp_data->req_content_append;
			return (u_char *) &long_return;
		CASELONG(META2_REQ_CONTENT_ADD, req_content_add);
		CASELONG(META2_REQ_CONTENT_APPEND, req_content_append);
		CASELONG(META2_REQ_CONTENT_COMMIT, req_content_commit);
		CASELONG(META2_REQ_CHUNK_COMMIT, req_chunk_commit);
		CASELONG(META2_REQ_CONTENT_GET, req_content_retrieve);
		CASELONG(META2_REQ_RPLCONTENT, req_rplcontent);
		CASELONG(META2_REQ_STATCONTENT, req_statcontent);

		CASELONG(META2_TIME_CREATE, time_create);
		case META2_TIME_ALLGETS:
			long_return = snmp_data->time_content_retrieve
				+ snmp_data->time_maintenance_getchunks
				+ snmp_data->time_maintenance_getcontent;
			return (u_char *) &long_return;
		CASELONG(META2_TIME_LIST, time_list);
		CASELONG(META2_TIME_CLOSE, time_close);
		CASELONG(META2_TIME_DESTROY, time_destroy);
		CASELONG(META2_TIME_CONTENT_RM, time_content_remove);
		CASELONG(META2_TIME_OPEN, time_open);
		case META2_TIME_CONTENT_ALLPUTS:
			long_return = snmp_data->time_content_add + snmp_data->time_content_append;
			return (u_char *) &long_return;
		CASELONG(META2_TIME_CONTENT_ADD, time_content_add);
		CASELONG(META2_TIME_CONTENT_APPEND, time_content_append);
		CASELONG(META2_TIME_CONTENT_COMMIT, time_content_commit);
		CASELONG(META2_TIME_CHUNK_COMMIT, time_chunk_commit);
		CASELONG(META2_TIME_CONTENT_GET, time_content_retrieve);
		CASELONG(META2_TIME_RPLCONTENT, time_rplcontent);
		CASELONG(META2_TIME_STATCONTENT, time_statcontent);

		CASELONG(META2_REQ_RAW_GETCONTENT, req_maintenance_getcontent);
		CASELONG(META2_REQ_RAW_GETCHUNK, req_maintenance_getchunks);
		CASELONG(META2_REQ_RAW_SETCONTENT, req_maintenance_setcontent);
		CASELONG(META2_REQ_RAW_SETCHUNK, req_maintenance_setchunks);
		CASELONG(META2_REQ_RAW_DELCONTENT, req_maintenance_delcontent);
		CASELONG(META2_REQ_RAW_DELCHUNK, req_maintenance_delchunks);
		CASELONG(META2_REQ_RAW_OTHER, req_maintenance_other);

		CASELONG(META2_TIME_RAW_GETCONTENT, time_maintenance_getcontent);
		CASELONG(META2_TIME_RAW_GETCHUNK, time_maintenance_getchunks);
		CASELONG(META2_TIME_RAW_SETCONTENT, time_maintenance_setcontent);
		CASELONG(META2_TIME_RAW_SETCHUNK, time_maintenance_setchunks);
		CASELONG(META2_TIME_RAW_DELCONTENT, time_maintenance_delcontent);
		CASELONG(META2_TIME_RAW_DELCHUNK, time_maintenance_delchunks);
		CASELONG(META2_TIME_RAW_OTHER, time_maintenance_other);

		CASELONG(META2_REQ_PROP_SET_CONTENT,	req_prop_set_content);
		CASELONG(META2_REQ_PROP_SET_CONTAINER,	req_prop_set_container);
		CASELONG(META2_REQ_PROP_GET_CONTENT,	req_prop_get_content);
		CASELONG(META2_REQ_PROP_GET_CONTAINER,	req_prop_get_container);
		CASELONG(META2_REQ_PROP_RM_CONTENT,	req_prop_rm_content);
		CASELONG(META2_REQ_PROP_RM_CONTAINER,	req_prop_rm_container);
		CASELONG(META2_REQ_PROP_RPL_SET_CONTAINER,	req_prop_rpl_set_container);
		CASELONG(META2_REQ_PROP_RPL_RM_CONTAINER,	req_prop_rpl_rm_container);

		CASELONG(META2_TIME_PROP_SET_CONTENT,	time_prop_set_content);
		CASELONG(META2_TIME_PROP_SET_CONTAINER,	time_prop_set_container);
		CASELONG(META2_TIME_PROP_GET_CONTENT,	time_prop_get_content);
		CASELONG(META2_TIME_PROP_GET_CONTAINER,	time_prop_get_container);
		CASELONG(META2_TIME_PROP_RM_CONTENT,	time_prop_rm_content);
		CASELONG(META2_TIME_PROP_RM_CONTAINER,	time_prop_rm_container);
		CASELONG(META2_TIME_PROP_RPL_SET_CONTAINER,	time_prop_rpl_set_container);
		CASELONG(META2_TIME_PROP_RPL_RM_CONTAINER,	time_prop_rpl_rm_container);

		CASELONG(META2_NB_THREAD, nb_thread);

		default:
			DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
				__FUNCTION__, vp->magic, str_oid));
			return NULL;
	}
}

u_char*
var_rawx_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct rawx_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_local_services();

	if (rawx_max_index < 0 || rawx_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, rawx_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;

	snmp_data = rawx_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
		case RAWX_NUMBER:
			long_return = (long) count_rawx;
			return (u_char *) &long_return;

		case RAWX_INDEX:
			long_return = (long) idx + 1;
			return (u_char *) &long_return;

		case RAWX_NAMESPACE:
			*var_len = strlen(snmp_data->namespace);
			return (u_char *) snmp_data->namespace;

		case RAWX_VOLUME:
			*var_len = strlen(snmp_data->volume);
			return (u_char *) snmp_data->volume;

		case RAWX_ADDR:
			*var_len = strlen(snmp_data->addr);
			return (u_char *) snmp_data->addr;

		CASELONG(RAWX_SCORE, score);
		CASELONG(RAWX_FREE_CHUNK, free_chunk);
		CASELONG(RAWX_IO_IDLE, io_idle);
		CASELONG(RAWX_REQ_ALL, req_all);
		CASELONG(RAWX_REQ_GET, req_get);
		CASELONG(RAWX_REQ_PUT, req_put);
		CASELONG(RAWX_REQ_DEL, req_del);
		CASELONG(RAWX_REQ_INFO, req_info);
		CASELONG(RAWX_REQ_STAT, req_stat);
		CASELONG(RAWX_REQ_RAW, req_raw);
		CASELONG(RAWX_REQ_OTHER, req_other);
		CASELONG(RAWX_REPLY_2XX, rep_2xx);
		CASELONG(RAWX_REPLY_4XX, rep_4xx);
		CASELONG(RAWX_REPLY_5XX, rep_5xx);
		CASELONG(RAWX_REPLY_403, rep_403);
		CASELONG(RAWX_REPLY_404, rep_404);
		CASELONG(RAWX_REPLY_OTHER, rep_other);
		CASELONG(RAWX_BYTES_READ, bytes_read);
		CASELONG(RAWX_BYTES_WRITTEN, bytes_written);

		default:
			DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
				__FUNCTION__, vp->magic, str_oid));
			return NULL;
	}
}

u_char*
var_saver_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct saver_snmp_data *snmp_data = NULL;

	reload_local_services();

	if (saver_max_index < 0 || saver_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, saver_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;
	snmp_data = saver_snmp_data[idx];

	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
		case SAVER_NUMBER:
			long_return = (long) count_saver;
			return (u_char *) &long_return;

		case SAVER_INDEX:
			long_return = (long) idx + 1;
			return (u_char *) &long_return;

		case SAVER_NAMESPACE:
			*var_len = strlen(snmp_data->namespace);
			return (u_char *) snmp_data->namespace;

		case SAVER_ADDR:
			*var_len = strlen(snmp_data->addr);
			return (u_char *) snmp_data->addr;

		CASELONG(SAVER_SCORE, score);
		CASELONG(SAVER_REQ_PUSH, req_push);
		CASELONG(SAVER_REQ_STATUS, req_status);
		CASELONG(SAVER_WORKERS_BYTES, workers_bytes);
		CASELONG(SAVER_WORKERS_OK, workers_ok);
		CASELONG(SAVER_WORKERS_FAILED, workers_ko);

		default:
			DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
				__FUNCTION__, vp->magic, str_oid));
			return NULL;
	}
}

u_char*
var_tsmx_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct tsmx_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_local_services();

	if (tsmx_max_index < 0 || tsmx_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, tsmx_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;

	snmp_data = tsmx_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
	    case TSMX_NUMBER:
		long_return = (long) count_tsmx;
		return (u_char *) &long_return;

	    case TSMX_INDEX:
		long_return = (long) idx + 1;
		return (u_char *) &long_return;

	    case TSMX_NAMESPACE:
		*var_len = strlen(snmp_data->namespace);
		return (u_char *) snmp_data->namespace;

	    case TSMX_ADDR:
		*var_len = strlen(snmp_data->addr);
		return (u_char *) snmp_data->addr;

	    CASELONG(TSMX_SCORE, score);
	    CASELONG(TSMX_IDLE_LOG, idle_log);
	    CASELONG(TSMX_IDLE_DB, idle_db);
	    CASELONG(TSMX_IDLE_STG, idle_stg);
	    CASELONG(TSMX_REQ_PUT, req_put);
	    CASELONG(TSMX_REQ_GET, req_get);
	    CASELONG(TSMX_REQ_DEL, req_del);
	    CASELONG(TSMX_FAILED,  failed);
	    CASELONG(TSMX_BYTES_IN, bytes_in);
	    CASELONG(TSMX_BYTES_OUT, bytes_out);
	    
	    default:
		DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}
}

u_char*
var_solr_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct solr_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_local_services();

	if (solr_max_index < 0 || solr_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, solr_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;

	snmp_data = solr_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
	    case SOLR_NUMBER:
		long_return = (long) count_solr;
		return (u_char *) &long_return;

	    case SOLR_INDEX:
		long_return = (long) idx + 1;
		return (u_char *) &long_return;

	    case SOLR_NAMESPACE:
		*var_len = strlen(snmp_data->namespace);
		return (u_char *) snmp_data->namespace;

	    case SOLR_ADDR:
		*var_len = strlen(snmp_data->addr);
		return (u_char *) snmp_data->addr;

	    CASELONG(SOLR_SCORE, score);
	    CASELONG(SOLR_REQ_SEARCH, req_search);
	    CASELONG(SOLR_REQ_UPDATE, req_update);
	    CASELONG(SOLR_TIME_SEARCH, time_search);
	    CASELONG(SOLR_TIME_UPDATE, time_update);
	    CASELONG(SOLR_COMMITS, commits);
	    
	    default:
		DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}
}

u_char*
var_rplx_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct rplx_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_local_services();

	if (rplx_max_index < 0 || rplx_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, rplx_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;
	snmp_data = rplx_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
		case RPLX_NUMBER:
			long_return = (long) count_rplx;
			return (u_char *) &long_return;

		case RPLX_INDEX:
			long_return = (long) idx + 1;
			return (u_char *) &long_return;

		case RPLX_NAMESPACE:
			*var_len = strlen(snmp_data->namespace);
			return (u_char *) snmp_data->namespace;

		case RPLX_ADDR:
			*var_len = strlen(snmp_data->addr);
			return (u_char *) snmp_data->addr;

		CASELONG(RPLX_SCORE, score);
		CASELONG(RPLX_WORKER_CUR, worker_current);
		CASELONG(RPLX_WORKER_IDLE, worker_idle);
		CASELONG(RPLX_WORKER_MAX, worker_max);
		CASELONG(RPLX_WORKER_QUEUE, worker_queue);
		CASELONG(RPLX_REQ_PUSH, req_push);
		CASELONG(RPLX_REQ_STATUS, req_status);
		CASELONG(RPLX_REQ_TOTAL, req_total);
		CASELONG(RPLX_TIME_PUSH, time_push);
		CASELONG(RPLX_TIME_STATUS, time_status);
		CASELONG(RPLX_TIME_TOTAL, time_total);

		CASELONG(RPLX_NB_THREAD, nb_thread);

		default:
			DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
				__FUNCTION__, vp->magic, str_oid));
			return NULL;
	}
}

u_char*
var_evt_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct evt_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_events();

	if (evt_max_index < 0 || evt_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, evt_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;
	snmp_data = evt_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
		case EVT_NUMBER:
			long_return = (long) count_evt;
			return (u_char *) &long_return;

		case EVT_INDEX:
			long_return = (long) idx + 1;
			return (u_char *) &long_return;

		case EVT_NAMESPACE:
			*var_len = strlen(snmp_data->namespace);
			return (u_char *) snmp_data->namespace;

		CASELONG(EVT_INCOMING_NB, incoming_nb);
		CASELONG(EVT_INCOMING_AGE, incoming_age);
		CASELONG(EVT_INCOMING_OLDEST, incoming_oldest);
		CASELONG(EVT_PENDING_NB, pending_nb);
		CASELONG(EVT_PENDING_AGE, pending_age);
		CASELONG(EVT_PENDING_OLDEST, pending_oldest);

		default:
			DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
				__FUNCTION__, vp->magic, str_oid));
			return NULL;
	}
}

u_char*
var_csc_entry(struct variable * vp, oid * name, size_t * length, int exact, size_t * var_len, WriteMethod ** write_method)
{
	gchar str_oid[256] = {0,0};
	int idx;
	struct csc_snmp_data *snmp_data = NULL;

	oid_to_string(name, *length, str_oid, sizeof(str_oid));
	reload_conscience();

	if (csc_max_index < 0 || csc_snmp_data == NULL) {
		DEBUGMSGTL(("grid", "%s no such entry magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	if (header_simple_table(vp, name, length, exact, var_len, write_method, csc_max_index+1)) {
		DEBUGMSGTL(("grid", "%s end of table magic=%d oid=%s\n",
			__FUNCTION__, vp->magic, str_oid));
		return NULL;
	}

	idx = (int) name[*length - 1] - 1;
	snmp_data = csc_snmp_data[idx];
	if (!snmp_data) {
		DEBUGMSGTL(("grid", "%s stats not found idx=%d oid=%s\n",
			__FUNCTION__, idx, str_oid));
		return NULL;
	}

	switch (vp->magic) {
		case CSC_NUMBER:
			long_return = (long) count_csc;
			return (u_char *) &long_return;

		case CSC_INDEX:
			long_return = (long) idx + 1;
			return (u_char *) &long_return;

		case CSC_NAMESPACE:
			*var_len = strlen(snmp_data->namespace);
			return (u_char *) snmp_data->namespace;

		case CSC_ADDR:
			*var_len = strlen(snmp_data->addr);
			return (u_char *) snmp_data->addr;

		CASELONG(CSC_NB_THREAD, nb_thread);
		CASELONG(CSC_NB_RAWX, nb_rawx);
		CASELONG(CSC_NB_RAWX_ONLINE, nb_rawx_online);

		default:
			DEBUGMSGTL(("grid", "%s bad magic magic=%d oid=%s\n",
				__FUNCTION__, vp->magic, str_oid));
			return NULL;
	}
}
