#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <sqliterepo/sqliterepo.h>
#include <meta2/remote/meta2_remote.h>
#include <server/grid_daemon.h>
#include <server/transport_gridd.h>

#include "./meta1_backend.h"
#include "./meta1_prefixes.h"
#include "./meta1_remote.h"
#include "./meta1_gridd_dispatcher.h"
#include "./internals.h"

#define EXTRACT_STRING(Name,Dst,Mandatory) do { \
	err = message_extract_string(reply->request, Name, Dst, sizeof(Dst)); \
	if (NULL != err) { \
		if (!(Mandatory)) { \
			g_clear_error(&err); \
			memset((Dst), 0, sizeof(Dst)); \
		} else { \
			reply->send_error(0, err); \
			return TRUE; \
		} \
	} \
} while (0)

#define EXTRACT_CID(CID) do { \
	err = message_extract_cid(reply->request, "CONTAINER_ID", &CID); \
	if (NULL != err) { \
		reply->send_error(0, err); \
		return TRUE; \
	} else { container_id_to_string(cid, strcid, sizeof(strcid)); }\
} while (0)

#define EXTRACT_FLAG(Name,Flag) do { \
	err = message_extract_flag(reply->request, Name, FALSE, &(Flag)); \
	if (NULL != err) { \
		reply->send_error(0, err); \
		return TRUE; \
	} \
} while (0)

#define EXTRACT_CNAME(Dst) EXTRACT_STRING("CONTAINER_NAME", Dst, TRUE)
#define EXTRACT_VNS(Dst) EXTRACT_STRING("VIRTUAL_NAMESPACE", Dst, FALSE)
#define EXTRACT_NS(Dst) EXTRACT_STRING("NAMESPACE", Dst, TRUE)
#define EXTRACT_SRVTYPE(Dst,Mandatory) EXTRACT_STRING("SRVTYPE", Dst, Mandatory)

static GQuark gquark_log = 0;

static gsize m1b_bufsize_listbypref = 16384;

static gboolean
srv_to_addr(const gchar *srv, struct addr_info_s *a)
{
	const gchar *type, *addr;
	type = strchr(srv, '|') + 1; /* skip the sequence number*/
	addr = strchr(type, '|') + 1; /* skip the service type */
	if (!addr)
		return FALSE;
	return grid_string_to_addrinfo(addr, strchr(addr, '|'), a);
}

static GSList *
singleton_addrl(const struct addr_info_s *ai)
{
	return g_slist_append(NULL, g_memdup(ai, sizeof(*ai)));
}

static GSList *
convert_urlv_to_addrl(gchar **urlv)
{
	gchar **u;
	GSList *result = NULL;

	if (!urlv)
		return NULL;

	for (u=urlv; *u ;u++) {
		struct addr_info_s ai;
		memset(&ai, 0, sizeof(ai));
		if (!srv_to_addr(*u, &ai))
			GRID_DEBUG("Invalid META2 URL [%s]", *u);
		else
			result = g_slist_prepend(result, g_memdup(&ai, sizeof(ai)));
	}

	g_strfreev(urlv);
	return result;
}

static GByteArray *
marshall_addrl(GSList *l, GError **err)
{
	GByteArray *gba;
	
	gba = addr_info_marshall_gba(l, NULL);
	if (l) {
		g_slist_foreach(l, addr_info_gclean, NULL);
		g_slist_free(l);
	}

	if (gba)
		return gba;

	*err = g_error_new(gquark_log, 500, "Encoding error (addr_info_t)");
	return NULL;
}

static GByteArray *
marshall_stringv(gchar **v)
{
	GByteArray *result = metautils_encode_lines(v);
	g_strfreev(v);
	return result;
}

/* -------------------------------------------------------------------------- */

static GError *
_stat_container(struct meta1_backend_s *m1, const container_id_t cid,
		struct meta1_raw_container_s **result)
{
	GError *err;
	struct meta1_raw_container_s *raw;
	gchar **names, **allsrv;

	/* Get the meta1 name */
	err = meta1_backend_info_container(m1, cid, &names);
	if (err != NULL)
		return err;

	/* Get the meta2 services */
	err = meta1_backend_get_container_all_services(m1, cid, "meta2", &allsrv);
	if (err != NULL) {
		g_strfreev(names);
		return err;
	}
	
	/* OK, we have all the data */
	raw = g_malloc0(sizeof(*raw));
	memcpy(raw->id, cid, sizeof(container_id_t));
	g_strlcpy(raw->name, names[0], sizeof(raw->name)-1);
	g_strfreev(names);
	raw->meta2 = convert_urlv_to_addrl(allsrv);

	*result = raw;
	return NULL;
}

static GError *
_create_on_meta2(const gchar *srv, const gchar *vns, const gchar *cname,
		container_id_t cid, struct addr_info_s *m2addr)
{
	gboolean rc;
	GError *err = NULL;

	GRID_DEBUG("Creation attempt on META2 at [%s]", srv);

	if (!srv_to_addr(srv, m2addr))
		return g_error_new(gquark_log, 500, "Invalid address (%d %s)",
				errno, strerror(errno));

	rc = vns && *vns
		? meta2_remote_container_create_v2(m2addr, 30000, &err, cid, cname, vns)
		: meta2_remote_container_create(m2addr, 30000, &err, cid, cname);

	if (!rc) {
		if (!err)
			return g_error_new(gquark_log, 502,
					"Unknown error when contacting META2");
		g_prefix_error(&err, "META2 error : ");
		return err;
	}

	return NULL;
}

static GError*
_update_container_quota(struct meta1_backend_s *m1,
		struct container_info_s *cinfo)
{
	GError *e0 = NULL;
	gint rc;
	sqlite3_stmt *stmt = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	e0 = meta1_backend_open_base(m1, cinfo->id, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (NULL != e0)
		return e0;

	e0 = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != e0) {
		sqlx_repository_unlock_and_close_noerror(sq3);
		return e0;
	}

	sqlite3_prepare_debug(rc, sq3->db, "UPDATE properties SET"
			" value = ?"
			" WHERE cid = ?"
			" AND name = 'meta2.quota'", -1, &stmt, NULL);
	(void) sqlite3_bind_int64(stmt, 1, cinfo->size);
	(void) sqlite3_bind_blob(stmt, 2, cinfo->id,
			sizeof(container_id_t), NULL);

	for (rc=SQLITE_ROW; rc == SQLITE_ROW ;)
		rc = sqlite3_step(stmt);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		e0 = SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	if (!e0 && sqlite3_changes(sq3->db) <= 0) {
		sqlite3_prepare_debug(rc, sq3->db,
				"INSERT INTO properties (cid,name,value)"
				" VALUES (?,?,?)", -1, &stmt, NULL);
		(void) sqlite3_bind_blob(stmt, 1, cinfo->id, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, "meta2.quota", sizeof("meta2.quota")-1, NULL);
		(void) sqlite3_bind_int64(stmt, 3, cinfo->size);

		for (rc=SQLITE_ROW; rc == SQLITE_ROW ;)
			rc = sqlite3_step(stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			e0 = SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	/* Commit then close the container's base */
	e0 = sqlx_transaction_end(repctx, e0);
	sqlx_repository_unlock_and_close_noerror(sq3);
	return e0;
}

static struct hc_url_s *
_forge_url(struct meta1_backend_s *m1, const char *vns, const char *hexid)
{
	struct hc_url_s *url = hc_url_empty();
	if(vns) {
		hc_url_set(url, HCURL_NS, vns);
	} else {
		char *ns = meta1_backend_get_ns_name(m1);
		hc_url_set(url, HCURL_NS, ns);
		g_free(ns);
	}
	hc_url_set(url, HCURL_HEXID, hexid);

	return url;
}

/* -------------------------------------------------------------------------- */

static gboolean
meta1_dispatch_v1_CREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	struct addr_info_s m2addr;
	container_id_t cid;
	gchar **result = NULL;
	gchar strcid[65], cname[256], vns[256];
	struct hc_url_s *url = NULL;

	/* Unpack the request */
	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_CNAME(cname);
	EXTRACT_VNS(vns);
	url = _forge_url(m1, vns, strcid);

	reply->subject("%s/%s|%s", vns, cname, strcid);

	/* Test if the container exsists */
	err = meta1_backend_get_container_all_services(m1, cid, "meta2", &result);
	if (NULL != err) {
		if (err->code != CODE_CONTAINER_NOTFOUND) {
			hc_url_clean(url);
			reply->send_error(0, err);
			return TRUE;
		}
		g_clear_error(&err);

		GRID_DEBUG("Creating the container reference");
		err = meta1_backend_create_container(m1, vns, cname, NULL);
		if (NULL != err) {
			hc_url_clean(url);
			reply->send_error(0, err);
			return TRUE;
		}
	}

	/* Associate a META2 to the container */
	if (result && !*result) {
		g_free(result);
		result = NULL;
	}
	if (!result) {
		GRID_TRACE("Meta2 election...");
		err = meta1_backend_get_container_service_available(m1, url, "meta2",
				FALSE, &result);
		if (NULL != err) {
			hc_url_clean(url);
			reply->send_error(0, err);
			return TRUE;
		}
	}

	/* Contact the meta2 and create a container on it */
	gchar **p_url;
	for (p_url=result; *p_url ;p_url++) {

		err = _create_on_meta2(*p_url, vns, cname, cid, &m2addr);
		if (!err) {
			GRID_DEBUG("Container created on META2");
			break;
		}

		if (err->code == CODE_CONTAINER_EXISTS) {
			GRID_DEBUG("Container already present on META2");
			break;
		}

		if (err->code >= 300) {
			GRID_DEBUG("Error when creating the container on META2 [%s]"
					" : code=%d message=%s",
					*p_url, err->code, err->message);
			break;
		}

		GRID_INFO("Network error : code=%d message=%s", err->code, err->message);
		g_clear_error(&err);
	}

	g_strfreev(result);
	hc_url_clean(url);

	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* Send the META2 address in the body of the reply ? */
	reply->add_body(marshall_addrl(singleton_addrl(&m2addr), NULL));

	GRID_DEBUG("Container created!");
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_v1_DESTROY(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65];

	(void) ignored;
	EXTRACT_CID(cid);
	reply->subject("%s", strcid);

	err = meta1_backend_destroy_m2_container(m1, cid);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_v1_GET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], **result;

	(void) ignored;
	EXTRACT_CID(cid);
	reply->subject("%s", strcid);

	err = meta1_backend_get_container_all_services(m1, cid, "meta2", &result);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}
	if (!result || !*result) {
		reply->send_error(0, g_error_new(gquark_log, CODE_CONTAINER_NOTFOUND,
					"Container exists but no META2 associated"));
		return TRUE;
	}

	reply->add_body(marshall_addrl(convert_urlv_to_addrl(result), &err));
	if (err) {
		g_prefix_error(&err, "ASN.1 encoding error : ");
		reply->send_error(500, err);
		return FALSE;
	}

	reply->send_reply(200, "OK");
	return TRUE;
}

#define CINFO(P) ((struct container_info_s*)(P))

static gboolean
meta1_dispatch_UPDATECONTAINERS(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err = NULL;
	GSList *list_of_cinfo = NULL, *l;

	(void) ignored;
	err = message_extract_body_encoded(reply->request, &list_of_cinfo,
			container_info_unmarshall);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (!list_of_cinfo)
		reply->subject("empty");
	else if (!list_of_cinfo->next) {
		gchar strcid[65];
		container_id_to_string(CINFO(list_of_cinfo->data)->id, strcid, sizeof(strcid));
		reply->subject("%s|%"G_GINT64_FORMAT, strcid, CINFO(list_of_cinfo->data)->size);
	}
	else
		reply->subject("%u", g_slist_length(list_of_cinfo));

	for (l=list_of_cinfo; l ;l=l->next) {
		if (NULL != (err = _update_container_quota(m1, l->data))) {
			reply->send_error(0, err);
			break;
		}
	}

	if (list_of_cinfo) {
		g_slist_foreach(list_of_cinfo, g_free1, NULL);
		g_slist_free(list_of_cinfo);
		list_of_cinfo = NULL;
	}

	if (!err)
		reply->send_reply(200, "OK");
	return TRUE;
}

static void
_manage_prefix(struct meta1_backend_s *m1, guint8 *prefix, sqlite3 *tmpdb)
{
	gchar sql[LIMIT_LENGTH_NSNAME + 128];

	int cb(void * u, int nbcols, char **vals, char **cols) {
		char *err_msg2 = NULL;

		(void) u;
		(void) nbcols;
		(void) cols;

		memset(sql, 0, sizeof(sql));
		g_snprintf(sql, sizeof(sql), "UPDATE vns SET size = size + %s "
				"WHERE vns = '%s'", vals[1], vals[0]);
		GRID_TRACE("_manage_prefix executing [%s]", sql);
		if (sqlite3_exec(tmpdb, sql, NULL, NULL, &err_msg2) != SQLITE_OK) {
			GRID_WARN("Could not update size for VNS %s: %s", vals[0], err_msg2);
		}
		sqlite3_free(err_msg2);
		err_msg2 = NULL;

		if (!sqlite3_changes(tmpdb)) { /* VNS not found */
			g_snprintf(sql, sizeof(sql), "INSERT INTO vns (vns,size) "
					"VALUES ('%s',%s)", vals[0], vals[1]);
			GRID_TRACE("_manage_prefix VNS not found, executing [%s]", sql);
			if (sqlite3_exec(tmpdb, sql, NULL, NULL, &err_msg2) != SQLITE_OK) {
				GRID_WARN("Could not set size for VNS %s: %s", vals[0], err_msg2);
			}
			sqlite3_free(err_msg2);
		}
		return 0;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	container_id_t cid;
	int rc = 0;
	char *err_msg = NULL;
	GError *err;

	memset(cid, 0, sizeof(container_id_t));
	memcpy(cid, prefix, 2);

	err = meta1_backend_open_base(m1, cid,
			M1V2_OPENBASE_MASTERONLY, &sq3);
	if (NULL != err) {
		// CODE_REDIRECT error is thrown when we are not master
		if (err->code == CODE_REDIRECT) {
			GRID_DEBUG("Not managing [%02X%02X]: not master (%s).",
					prefix[0], prefix[1], err->message);
		} else {
			GRID_WARN("Failed to manage [%02X%02X] : (%d) %s",
					prefix[0], prefix[1], err->code, err->message);
		}
		g_clear_error(&err);
		return;
	}

	rc = sqlite3_exec(sq3->db,
			"SELECT c.vns AS vns, SUM(p.value) as size "
			"FROM properties as p, containers AS c "
			"WHERE p.cid = c.cid AND p.name = 'meta2.quota' "
			"GROUP BY c.vns",
			cb, NULL, &err_msg);
	if (rc != SQLITE_OK) {
		GRID_WARN("An error occured during VNS size computation: %s", err_msg);
	}
	sqlite3_free(err_msg);
	sqlx_repository_unlock_and_close_noerror(sq3);
}

static GSList *
_serialize_db(sqlite3 *db)
{
	char *err_msg = NULL;
	GSList *result = NULL;

	int cb(void * u, int nbcols, char **vals, char **cols) {
		(void) u;
		(void) nbcols;
		(void) cols;

		result = g_slist_prepend(result,
				key_value_pair_create(vals[0], (guint8*)vals[1], strlen(vals[1]) + 1));
		GRID_TRACE("serialized size=[%s] vns=[%s]", vals[1], vals[0]);
		return 0;
	}

	if (sqlite3_exec(db, "SELECT vns, size FROM vns", cb, NULL, &err_msg)
			!= SQLITE_OK) {
		GRID_WARN("Could not completely serialize VNS size: %s", err_msg);
	}
	sqlite3_free(err_msg);
	return result;
}

static gboolean
meta1_dispatch_GETVNSSTATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err = NULL;
	char *err_msg = NULL;
	int i;
	union {
		guint16 prefix;
		guint8 b[2];
	} u;
	struct meta1_prefixes_set_s *m1ps;

	(void) m1;
	(void) ignored;

	u.prefix = 0;
	m1ps = meta1_backend_get_prefixes(m1);

	sqlite3 *db = NULL;
	sqlite3_open(":memory:", &db);
	int rc = sqlite3_exec(db,
			"CREATE TABLE vns (vns TEXT PRIMARY KEY, size INTEGER NOT NULL)",
			NULL, NULL, &err_msg);
	if (rc != SQLITE_OK) {
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"Failed to create temporary table: (%d) %s", rc, err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		reply->send_error(CODE_INTERNAL_ERROR, err);
		return TRUE;
	}
	sqlite3_free(err_msg);

	for (i=0; i<65536 ;i++,u.prefix++) {
		if (!grid_main_is_running())
			break;
		if (!meta1_prefixes_is_managed(m1ps, &(u.b[0])))
			continue;
		if (!meta1_backend_base_already_created(m1, &(u.b[0])))
			continue;
		_manage_prefix(m1, &(u.b[0]), db);

		reply->send_reply(100, "Prefix managed");
	}

	/* Serialize the DB content, then close it */
	GSList *kvl = _serialize_db(db);
	sqlite3_close(db);
	GByteArray *gba = key_value_pairs_marshall_gba(kvl, &err);
	g_slist_free_full(kvl, (GDestroyNotify)key_value_pair_clean);

	if (!gba) {
		reply->send_error(500, err);
		return TRUE;
	}

	reply->add_body(gba);
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_NOTIMPL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	(void) m1;
	(void) ignored;

	reply->send_error(500, g_error_new(gquark_log, 500, "Not implemented"));
	return TRUE;
}

static gboolean
meta1_dispatch_v1_BYID(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65];
	struct meta1_raw_container_s *raw = NULL;

	(void) ignored;
	EXTRACT_CID(cid);
	reply->subject("%s", strcid);

	err = _stat_container(m1, cid, &raw);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		GByteArray *gba = meta1_raw_container_marshall(raw, NULL);
		meta1_raw_container_clean(raw);
		reply->add_body(gba);
		reply->send_reply(200, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v1_BYNAME(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar cname[256], vns[256];
	struct meta1_raw_container_s *raw = NULL;

	(void) ignored;
	EXTRACT_VNS(vns);
	EXTRACT_CNAME(cname);
	reply->subject("%s/%s", vns, cname);

	meta1_name2hash(cid, vns, cname);

	err = _stat_container(m1, cid, &raw);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		GByteArray *gba = meta1_raw_container_marshall(raw, NULL);
		meta1_raw_container_clean(raw);
		reply->add_body(gba);
		reply->send_reply(200, "OK");
	}
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gboolean
meta1_dispatch_v2_CREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid, _cid;
	gchar strcid[65], ns[256], cname[256];

	(void) ignored;
	EXTRACT_NS(ns);
	EXTRACT_CID(cid);
	EXTRACT_CNAME(cname);
	reply->subject("%s/%s|%s", ns, cname, strcid);

	memset(_cid, 0, sizeof(_cid));
	err = meta1_backend_create_container(m1, ns, cname, &_cid);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_header("CONTAINER_ID", metautils_gba_from_cid(_cid));
		reply->send_reply(200, "Created");
	}
	return TRUE;
}

static gboolean
meta1_dispatch_v2_DESTROY(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gboolean force = FALSE;
	gchar strcid[65], ns[256];

	(void) ignored;
	EXTRACT_NS(ns);
	EXTRACT_CID(cid);
	reply->subject("%s/%s|%d", ns, strcid, force);

	if (NULL != (err = message_extract_flag(reply->request, "FORCE", FALSE, &force))) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = meta1_backend_destroy_container(m1, cid, force);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_v2_HAS(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar **info = NULL;
	gchar strcid[65], ns[256];

	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	reply->subject("%s/%s", ns, strcid);
	
	if (NULL != (err = meta1_backend_info_container(m1, cid, &info))) {
		reply->send_error(0, err);
		return TRUE;
	}
	else {
		reply->add_body(marshall_stringv(info));
		reply->send_reply(200, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_GETAVAIL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gboolean dryrun = FALSE;
	gchar strcid[65], srvtype[256], ns[256];
	gchar **result = NULL;
	struct hc_url_s *url = NULL;

	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	EXTRACT_SRVTYPE(srvtype, TRUE);
	EXTRACT_FLAG(NAME_HEADER_DRYRUN, dryrun);
	url = _forge_url(m1, ns, strcid);

	reply->subject("%s/%s|%s", ns, strcid, srvtype);

	err = meta1_backend_get_container_service_available(m1, url, srvtype,
			dryrun, &result);

	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv(result));
		reply->send_reply(200, "OK");
	}

	hc_url_clean(url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_NEW(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gboolean dryrun = FALSE;
	gchar strcid[65], srvtype[256], ns[256];
	gchar **result = NULL;
	struct hc_url_s *url = NULL;

	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	EXTRACT_SRVTYPE(srvtype, TRUE);
	EXTRACT_FLAG(NAME_HEADER_DRYRUN, dryrun);
	reply->subject("%s/%s|%s", ns, strcid, srvtype);
	url = _forge_url(m1, ns, strcid);

	err = meta1_backend_get_container_new_service(m1, url, srvtype, dryrun,
			&result);

	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv(result));
		reply->send_reply(200, "OK");
	}
	hc_url_clean(url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_OPENALL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	unsigned int count_errors = 0;
	int i;
	union {
		guint16 prefix;
		guint8 b[2];
		container_id_t cid;
	} u;
	struct meta1_prefixes_set_s *m1ps;

	(void) ignored;
	u.prefix = 0;
	m1ps = meta1_backend_get_prefixes(m1);

	for (i=0; i<65536 ;i++,u.prefix++) {
		if (!grid_main_is_running())
			break;
		if (meta1_prefixes_is_managed(m1ps, &(u.b[0]))) {
			struct sqlx_sqlite3_s *sq3 = NULL;
			GError *err;

			err = meta1_backend_open_base(m1, u.cid, M1V2_OPENBASE_LOCAL, &sq3);
			if (!err)
				sqlx_repository_unlock_and_close_noerror(sq3);
			else {
				GRID_WARN("META1 open error [%02X%02X] : (%d) %s",
						u.b[0], u.b[1], err->code, err->message);
				g_clear_error(&err);
				++ count_errors;
			}
		}
	}

	if (count_errors)
		reply->send_error(500, g_error_new(gquark_log, 500,
					"%u bases not opened", count_errors));
	else
		reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_SET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], ns[LIMIT_LENGTH_NSNAME], *url = NULL;

	(void) ignored;
	EXTRACT_NS(ns);
	EXTRACT_CID(cid);
	if (NULL != (err = message_extract_body_string(reply->request, &url))) {
		reply->send_error(400, err);
		return TRUE;
	}
	reply->subject("%s/%s|%s", ns, strcid, url);

	err = meta1_backend_force_service(m1, cid, url);
	g_free(url);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_SETARG(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], ns[LIMIT_LENGTH_NSNAME], *url = NULL;

	(void) ignored;
	EXTRACT_NS(ns);
	EXTRACT_CID(cid);
	reply->subject("%s/%s|%s", ns, strcid, url);
	if (NULL != (err = message_extract_body_string(reply->request, &url))) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = meta1_backend_set_service_arguments(m1, cid, url);
	g_free(url);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_DELETE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], srvtype[256], ns[256], **urlv = NULL;

	(void) ignored;
	EXTRACT_NS(ns);
	EXTRACT_CID(cid);
	EXTRACT_SRVTYPE(srvtype, TRUE);
	reply->subject("%s/%s|%s", ns, strcid, srvtype);
	if (NULL != (err = message_extract_body_strv(reply->request, &urlv))) {
		reply->send_error(400, err);
		return TRUE;
	}

	EXTRA_ASSERT(urlv != NULL);
	GRID_TRACE("%u services to be deleted", g_strv_length(urlv));

	err = meta1_backend_del_container_services(m1, cid, srvtype, urlv);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");

	g_strfreev(urlv);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_GETALL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], srvtype[256], ns[256];
	gchar **result = NULL;
	
	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	EXTRACT_SRVTYPE(srvtype, FALSE);
	reply->subject("%s/%s|%s", ns, strcid, srvtype);

	err = meta1_backend_get_container_all_services(m1, cid, srvtype, &result);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv(result));
		reply->send_reply(200, "OK");
	}
	return TRUE;
}


static gboolean 
meta1_dispatch_v2_SRV_GETALLonM1(struct gridd_reply_ctx_s *reply,
        struct meta1_backend_s *m1, gpointer ignored)
{
    GError *err;
    gchar ns[LIMIT_LENGTH_NSNAME];
    container_id_t prefix;
    gsize prefix_size;
	gchar **result = NULL;

    (void) ignored;

    memset(prefix, 0, sizeof(container_id_t));
    prefix_size = sizeof(container_id_t);

	EXTRACT_NS(ns);
    if ((err = message_extract_prefix(reply->request, "PREFIX", prefix, &prefix_size))) {
		reply->send_error(0, err); 
        return TRUE;
	}

    gchar strpfx[65];
    container_id_to_string(prefix, strpfx, sizeof(strpfx));
    reply->subject("%s/%s", ns, strpfx);
    reply->send_reply(100, "Received");
	err = meta1_backend_get_all_services(m1, prefix, &result); 
    if (NULL != err)
        reply->send_error(0, err);
    else {
        reply->add_body(marshall_stringv(result));
        reply->send_reply(200, "OK");
    }
	
    return TRUE;
}


static gboolean
meta1_dispatch_v2_CID_PROPGET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], ns[256], **strv = NULL, **result = NULL;

	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	reply->subject("%s/%s", ns, strcid);
	if (NULL != (err = message_extract_body_strv(reply->request, &strv))) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = meta1_backend_get_container_properties(m1, cid, strv, &result);
	g_strfreev(strv);
	strv = NULL;

	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv(result));
		reply->send_reply(200, "OK");
	}
	return TRUE;
}

static gboolean
meta1_dispatch_v2_CID_PROPSET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], ns[256], **strv = NULL;

	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	reply->subject("%s/%s", ns, strcid);
	if (NULL != (err = message_extract_body_strv(reply->request, &strv))) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = meta1_backend_set_container_properties(m1, cid, strv);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_v2_CID_PROPDEL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	container_id_t cid;
	gchar strcid[65], ns[256], **strv = NULL;

	(void) ignored;
	EXTRACT_CID(cid);
	EXTRACT_NS(ns);
	reply->subject("%s/%s", ns, strcid);

	if (NULL != (err = message_extract_body_strv(reply->request, &strv))) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = meta1_backend_del_container_properties(m1, cid, strv);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(200, "OK");
	return TRUE;
}


struct reflist_ctx_s
{
	struct gridd_reply_ctx_s *reply;
	GByteArray *gba;
};

static void
reflist_hook(gpointer p, const gchar *ns, const gchar *ref)
{
	struct reflist_ctx_s *ctx = p;

	if (!ctx->gba)
		ctx->gba = g_byte_array_new();

	g_byte_array_append(ctx->gba, (guint8*)ns, strlen(ns));
	g_byte_array_append(ctx->gba, (guint8*)"/", 1);
	g_byte_array_append(ctx->gba, (guint8*)ref, strlen(ref));
	g_byte_array_append(ctx->gba, (guint8*)"\n", 1);

	if (ctx->gba->len > m1b_bufsize_listbypref) {
		ctx->reply->add_body(ctx->gba);
		ctx->gba = NULL;
		ctx->reply->send_reply(206, "Partial content");
	}
}

static void
reflist_final(struct reflist_ctx_s *ctx, GError *err)
{
	if (err) {
		if (ctx->gba)
			g_byte_array_free(ctx->gba, TRUE);
		ctx->reply->send_error(0, err);
	}
	else {
		if (ctx->gba)
			ctx->reply->add_body(ctx->gba);
		ctx->reply->send_reply(200, "OK");
	}

	ctx->gba = NULL;
	ctx->reply = NULL;
}

static gboolean
meta1_dispatch_v2_SRV_LISTPREF(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct reflist_ctx_s reflist_ctx;
	GError *err;
	gchar ns[LIMIT_LENGTH_NSNAME];
	container_id_t prefix;
	gsize prefix_size;

	(void) ignored;

	reflist_ctx.gba = NULL;
	reflist_ctx.reply = reply;
	memset(prefix, 0, sizeof(container_id_t));
	prefix_size = sizeof(container_id_t);

	if (!(err = message_extract_prefix(reply->request, "PREFIX", prefix, &prefix_size))
			&& !(err = message_extract_string(reply->request, "NAMESPACE", ns, sizeof(ns))))
	{
		gchar strpfx[65];
		container_id_to_string(prefix, strpfx, sizeof(strpfx));
		reply->subject("%s/%s", ns, strpfx);
		reply->send_reply(100, "Received");
		err = meta1_backend_list_references(m1, prefix, reflist_hook, &reflist_ctx);
	}

	reflist_final(&reflist_ctx, err);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LISTSERV(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar ns[LIMIT_LENGTH_NSNAME], srvtype[LIMIT_LENGTH_SRVTYPE], url[256];
	container_id_t prefix;
	gsize prefix_size;
	struct reflist_ctx_s reflist_ctx;

	(void) ignored;

	reflist_ctx.gba = NULL;
	reflist_ctx.reply = reply;
	memset(prefix, 0, sizeof(container_id_t));
	prefix_size = sizeof(container_id_t);

	if (!(err = message_extract_prefix(reply->request, "PREFIX", prefix, &prefix_size))
			&& !(err = message_extract_string(reply->request, "NAMESPACE", ns, sizeof(ns)))
			&& !(err = message_extract_string(reply->request, "SRVTYPE", srvtype, sizeof(srvtype)))
			&& !(err = message_extract_string(reply->request, "URL", url, sizeof(url))))
	{
		gchar strpfx[65];
		container_id_to_string(prefix, strpfx, sizeof(strpfx));
		reply->subject("%s/%s/%s/%s", ns, strpfx, srvtype, url);
		reply->send_reply(100, "Received");
		err = meta1_backend_list_references_by_service(m1, prefix,
				srvtype, url, reflist_hook, &reflist_ctx);
	}

	reflist_final(&reflist_ctx, err);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_GET_PREFIX(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, gpointer ignored)
{
	gchar **result = NULL;
	struct meta1_prefixes_set_s *m1ps;

	(void) ignored;

	m1ps = meta1_backend_get_prefixes(m1);
	result = meta1_prefixes_get_all(m1ps);

	if ( result )
		reply->add_body(marshall_stringv(result));
	reply->send_reply(200, "OK");
	
	return TRUE;
}

static gboolean
meta1_dispatch_v2_UPDATE_M1_POLICY(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, gpointer ignored)
{
	gchar ns[LIMIT_LENGTH_NSNAME], srvtype[LIMIT_LENGTH_SRVTYPE], excludesrv[65], action[65];
	container_id_t prefix;
	container_id_t cid;
	gchar *result = NULL;
	gboolean checkonly = FALSE;
	GError *err = NULL;
	gboolean foundcontainer = TRUE, foundprefix=TRUE;
	gsize prefix_size = sizeof(container_id_t);
	gchar strcid[65];

	(void) ignored;

	memset(excludesrv, 0, sizeof(excludesrv));
	memset(&prefix,0, sizeof(container_id_t));
	memset(&cid,0, sizeof(container_id_t));
	memset(strcid, '\0', sizeof(strcid));

	EXTRACT_NS(ns);
	EXTRACT_SRVTYPE(srvtype,TRUE);
	EXTRACT_STRING("ACTION",action,TRUE);

	err = message_extract_prefix(reply->request, "PREFIX", prefix, &prefix_size);
	if ( NULL != err ) {
		foundprefix=FALSE;
		g_clear_error(&err);
	}
	else
		container_id_to_string(prefix, strcid, sizeof(strcid));

	err = message_extract_prefix(reply->request, "CONTAINER_ID", cid, &prefix_size);
	if ( NULL != err ) {
		foundcontainer=FALSE;
		g_clear_error(&err);
	}
	else
		container_id_to_string(cid, strcid, sizeof(strcid));

	/* Update ns from meta1 to support vns */
	if (foundcontainer) {
		gchar **names = NULL;
		if (NULL == (err = meta1_backend_info_container(m1, cid, &names))) {
			GRID_DEBUG("Found vns from meta1 : %s", names[0]);
			gchar *slash = g_strrstr(names[0], "/");
			memset(ns, '\0', sizeof(ns));
			g_strlcpy(ns, names[0], MIN(sizeof(ns), 1 + strlen(names[0]) - strlen(slash)));
			g_strfreev(names);
		}
	}

	EXTRACT_STRING("EXCLUDEURL",excludesrv,FALSE);
	err = message_extract_flag(reply->request, "CHECKONLY", FALSE, &checkonly);
	if ( NULL != err ) {
		g_clear_error(&err);
	}

	reply->subject("%s/%s/%s", ns, strcid, srvtype);

	// FVE: the next function can answer 303 so it's weird to answer 100 now
	// reply->send_reply(100, "Received");
	err = meta1_backend_update_m1_policy(m1, ns,
			(foundprefix? prefix : NULL),(foundcontainer? cid : NULL),
			srvtype, excludesrv, action, checkonly, &result);

	if (NULL != err)
		reply->send_error(0, err);
	else {
		GByteArray *gba = g_byte_array_new();
                g_byte_array_append(gba, (guint8*)result, strlen(result));
		g_byte_array_append(gba, (guint8*)"", 1);
		g_byte_array_set_size(gba, gba->len - 1);
		reply->add_body(gba);
		reply->send_reply(200, "OK");
	}

	g_free(result);

	return TRUE;

}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
meta1_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {

		/* META1 new fashion */
		{NAME_MSGNAME_M1V2_HAS,         (hook) meta1_dispatch_v2_HAS,           NULL},
		{NAME_MSGNAME_M1V2_CREATE,      (hook) meta1_dispatch_v2_CREATE,        NULL},
		{NAME_MSGNAME_M1V2_DESTROY,     (hook) meta1_dispatch_v2_DESTROY,       NULL},
		{NAME_MSGNAME_M1V2_SRVSET,      (hook) meta1_dispatch_v2_SRV_SET,       NULL},
		{NAME_MSGNAME_M1V2_SRVNEW,      (hook) meta1_dispatch_v2_SRV_NEW,       NULL},
		{NAME_MSGNAME_M1V2_SRVSETARG,   (hook) meta1_dispatch_v2_SRV_SETARG,    NULL},
		{NAME_MSGNAME_M1V2_SRVDEL,      (hook) meta1_dispatch_v2_SRV_DELETE,    NULL},
		{NAME_MSGNAME_M1V2_SRVALL,      (hook) meta1_dispatch_v2_SRV_GETALL,    NULL},
		{NAME_MSGNAME_M1V2_SRVALLONM1,  (hook) meta1_dispatch_v2_SRV_GETALLonM1,NULL},
		{NAME_MSGNAME_M1V2_SRVAVAIL,    (hook) meta1_dispatch_v2_SRV_GETAVAIL,  NULL},
		{NAME_MSGNAME_M1V2_CID_PROPGET, (hook) meta1_dispatch_v2_CID_PROPGET,   NULL},
		{NAME_MSGNAME_M1V2_CID_PROPSET, (hook) meta1_dispatch_v2_CID_PROPSET,   NULL},
		{NAME_MSGNAME_M1V2_CID_PROPDEL, (hook) meta1_dispatch_v2_CID_PROPDEL,   NULL},
		{NAME_MSGNAME_M1V2_OPENALL,     (hook) meta1_dispatch_v2_SRV_OPENALL,   NULL},
		{NAME_MSGNAME_M1V2_GETPREFIX,	(hook) meta1_dispatch_v2_GET_PREFIX,    NULL},
		{NAME_MSGNAME_M1V2_LISTBYPREF,  (hook) meta1_dispatch_v2_SRV_LISTPREF,  NULL},
		{NAME_MSGNAME_M1V2_LISTBYSERV,  (hook) meta1_dispatch_v2_SRV_LISTSERV,  NULL},
		{NAME_MSGNAME_M1V2_UPDATEM1POLICY,(hook) meta1_dispatch_v2_UPDATE_M1_POLICY, NULL},

		/* Old fashoned meta2-orentied requests */
		{NAME_MSGNAME_M1_GET,           (hook) meta1_dispatch_v1_GET,      NULL},
		{NAME_MSGNAME_M1_CREATE,        (hook) meta1_dispatch_v1_CREATE,   NULL},
		{NAME_MSGNAME_M1_DESTROY,       (hook) meta1_dispatch_v1_DESTROY,  NULL},
		{NAME_MSGNAME_M1_INFO,          (hook) meta1_dispatch_NOTIMPL,     NULL},
		{NAME_MSGNAME_M1_GETALLONM2,    (hook) meta1_dispatch_NOTIMPL,     NULL},
		{NAME_MSGNAME_M1_FORCECREATE,   (hook) meta1_dispatch_NOTIMPL,     NULL},
		{NAME_MSGNAME_M1_GETMATCHES,    (hook) meta1_dispatch_NOTIMPL,     NULL},
		{NAME_MSGNAME_M1_CONT_BY_ID,    (hook) meta1_dispatch_v1_BYID,     NULL},
		{NAME_MSGNAME_M1_CONT_BY_NAME,  (hook) meta1_dispatch_v1_BYNAME,   NULL},
		{NAME_MSGNAME_M1_MIGRATE_CONTAINER, (hook) meta1_dispatch_NOTIMPL, NULL},
		{NAME_MSGNAME_M1_UPDATE_CONTAINERS, (hook) meta1_dispatch_UPDATECONTAINERS, NULL},
		{NAME_MSGNAME_M1_GET_VNS_STATE,     (hook) meta1_dispatch_GETVNSSTATE,      NULL},

		{NULL, NULL, NULL}
	};

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	return descriptions;
}

