#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.backend"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fnmatch.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <sqliterepo/sqliterepo.h>
#include <meta2/remote/meta2_remote.h>

#include "./internals.h"
#include "./compound_types.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"



static GError *__get_container_all_services(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
        const gchar *srvtype, struct meta1_service_url_s ***result);



static struct meta1_service_url_s *
meta1_url_dup(struct meta1_service_url_s *u)
{
	struct meta1_service_url_s *result;

	if (!u)
		return NULL;

	result = g_malloc0(sizeof(struct meta1_service_url_s) + 1 + strlen(u->args));
	result->seq = u->seq;
	strcpy(result->srvtype, u->srvtype);
	strcpy(result->host, u->host);
	strcpy(result->args, u->args);

	return result;
}

static void
free_urlv(struct meta1_service_url_s **uv)
{
	struct meta1_service_url_s **p;

	if (!uv)
		return;

	for (p=uv; *p ;p++) {
		if (*p)
			g_free(*p);
	}

	g_free(uv);
}

static gint
urlv_get_max_seq(struct meta1_service_url_s **uv)
{
	gint seq = G_MININT;
	if (uv) {
		for (; *uv ;++uv) {
			if (seq < (*uv)->seq)
				seq = (*uv)->seq;
		}
	}
	return seq;
}

static gchar **
pack_urlv(struct meta1_service_url_s **uv)
{
	GPtrArray *tmp = g_ptr_array_new();
	for (; uv && *uv ;uv++)
		g_ptr_array_add(tmp, meta1_pack_url(*uv));
	g_ptr_array_add(tmp, NULL);
	return (gchar**)g_ptr_array_free(tmp, FALSE);
}

static struct meta1_service_url_s**
expand_url(struct meta1_service_url_s *u)
{
	gchar **p, **split;
	GPtrArray *tmp;

	if (!u)
		return g_malloc0(sizeof(void*));

	tmp = g_ptr_array_new();

	split = g_strsplit(u->host, ",", -1);
	for (p=split; p && *p ;p++) {
		struct meta1_service_url_s *newurl;

		newurl = meta1_url_dup(u);
		g_strlcpy(newurl->host, *p, sizeof(newurl->host));
		g_ptr_array_add(tmp, newurl);
	}

	if (split)
		g_strfreev(split);

	g_ptr_array_add(tmp, NULL);
	return (struct meta1_service_url_s**)g_ptr_array_free(tmp, FALSE);
}

static struct meta1_service_url_s**
expand_urlv(struct meta1_service_url_s **uv)
{
	GPtrArray *tmp;

	tmp = g_ptr_array_new();
	if (uv) {
		for (; *uv ;++uv) {
			struct meta1_service_url_s **p, **utmp;
			if (NULL != (utmp = expand_url(*uv))) {
				for (p=utmp; *p ;++p)
					g_ptr_array_add(tmp, *p);
				g_free(utmp);
			}
		}
	}

	g_ptr_array_add(tmp, NULL);
	return (struct meta1_service_url_s**)g_ptr_array_free(tmp, FALSE);
}

static struct service_info_s**
convert_url_to_serviceinfo(struct meta1_service_url_s *u, const gchar *excludeurl)
{
	GError *err = NULL;
	struct meta1_service_url_s **lst, **extracted=NULL;

	if (!u)
		return g_malloc0(sizeof(void*));

	GPtrArray *tmp = g_ptr_array_new();

	extracted = expand_url(u);

	for (lst=extracted; *lst ;++lst) {
		if ( g_strcmp0(excludeurl, (*lst)->host) == 0 ) {
			continue;
		}
		struct service_info_s *srv;
		srv = g_malloc0(sizeof(struct service_info_s));
		if ( !l4_address_init_with_url(&(srv->addr), (*lst)->host, &err)) {
			GRID_DEBUG("failed to build addr with url [%s], %s",(*lst)->host,err->message);
			g_clear_error(&err);
			continue;
		}
		g_strlcpy(srv->type,(*lst)->srvtype,sizeof(srv->type));
		g_ptr_array_add(tmp, srv);
	}

	g_ptr_array_add(tmp, NULL);
	if ( extracted )
		free_urlv(extracted);
	return (struct service_info_s**)g_ptr_array_free(tmp, FALSE);
}

static struct service_update_policies_s *
_policies(struct meta1_backend_s *m1, const char *ns_name)
{
	struct service_update_policies_s *pol;

	g_static_rw_lock_reader_lock(&m1->rwlock_ns_policies);
	pol = g_hash_table_lookup(m1->ns_policies, ns_name);
	if (!pol) {
		gchar *ns = meta1_backend_get_ns_name(m1);
		pol = g_hash_table_lookup(m1->ns_policies, ns);
		g_free(ns);
	}
	g_static_rw_lock_reader_unlock(&m1->rwlock_ns_policies);

	return pol;
}

//------------------------------------------------------------------------------

static GError *
__del_container_srvtype_properties(struct sqlx_sqlite3_s *sq3,
    const container_id_t cid, const gchar *srvtype)
{
   GError *err = NULL;
    gint rc;
    sqlite3_stmt *stmt = NULL;
    gchar* tmp_name = NULL;

    sqlite3_prepare_debug(rc, sq3->db,
        "DELETE FROM properties WHERE cid = ? AND name LIKE ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK && rc != SQLITE_DONE)
        err = M1_SQLITE_GERROR(sq3->db, rc);
    else {
        int len = strlen(srvtype)+10;
        tmp_name = g_malloc0(sizeof(gchar)*len);
        if (tmp_name) {
			g_snprintf(tmp_name, len, "%s.%%", srvtype);
			(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
			(void) sqlite3_bind_text(stmt, 2, tmp_name, strlen(tmp_name), NULL);
			 do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
			 if (rc != SQLITE_OK && rc != SQLITE_DONE)
			 	err = M1_SQLITE_GERROR(sq3->db, rc);
			sqlite3_finalize_debug(rc, stmt);
		}
	}

	return err;
}




static GError *
__del_container_all_services(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, const gchar *srvtype)
{
	sqlite3_stmt *stmt = NULL;
	GError *err = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db,
			"DELETE FROM services WHERE cid = ? AND srvtype = ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, strlen(srvtype), NULL);
		do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__del_container_one_service(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid,
		const gchar *srvtype, gint64 seq)
{
	static const gchar *sql = "DELETE FROM services WHERE cid = ? AND srvtype = ? AND seq = ?";
	sqlite3_stmt *stmt = NULL;
	GError *err = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, strlen(srvtype), NULL);
		(void) sqlite3_bind_int64(stmt, 3, seq);
		do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__del_container_services(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		const gchar *srvtype, gchar **urlv)
{
	gint64 seq;
	GError *err = NULL;
	guint line = 1;
	struct sqlx_repctx_s *repctx = NULL;

	if (NULL != (err = sqlx_transaction_begin(sq3, &repctx)))
		return err;

	if (!urlv || !*urlv)
		err = __del_container_all_services(sq3, cid, srvtype);
	else {
		for (; !err && *urlv ;urlv++,line++) {
			gchar *end = NULL;

			errno = 0;
			seq = g_ascii_strtoll(*urlv, &end, 10);
			if ((end == *urlv) || (!seq && errno==EINVAL))
				err = NEWERROR(400, "line %u : Invalid number", line);
			else
				err = __del_container_one_service(sq3, cid, srvtype, seq);
		}
	}

	// delete properties / services
	if (!err) {
		struct meta1_service_url_s **used = NULL;
		// list all services type of cid
		err = __get_container_all_services(sq3, cid, srvtype, &used);
		if (err) {
			g_prefix_error(&err, "Preliminary lookup error : ");
		} else {		
			if ((!used || !*used)){
				// service type not used for this container_id...
				// delete all properties about cid/srvtype
				__del_container_srvtype_properties(sq3, cid, srvtype);
			}
		}
	}

	return sqlx_transaction_end(repctx, err);
}

static GError *
__configure_service(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		struct meta1_service_url_s *url)
{
	static const gchar *sql = "UPDATE services SET args = ? "
		"WHERE cid = ? AND seq = ? AND srvtype = ?";
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	if (NULL != (err = sqlx_transaction_begin(sq3, &repctx)))
		return err;

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_text(stmt, 1, url->args, strlen(url->args), NULL);
		(void) sqlite3_bind_blob(stmt, 2, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_int64(stmt, 3, url->seq);
		(void) sqlite3_bind_text(stmt, 4, url->srvtype, strlen(url->srvtype), NULL);
		do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
		if (!err && !sqlite3_changes(sq3->db))
			err = NEWERROR(450, "Service not found");
	}

	return sqlx_transaction_end(repctx, err);
}

static GError *
__insert_service(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		struct meta1_service_url_s *url)
{
	static const gchar *sql = "INSERT INTO services (cid,srvtype,seq,url,args)"
		"VALUES (?,?,?,?,?)";
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	struct sqlx_repctx_s *repctx;

	if (NULL != (err = sqlx_transaction_begin(sq3, &repctx)))
		return err;

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, url->srvtype, strlen(url->srvtype), NULL);
		(void) sqlite3_bind_int64(stmt, 3, url->seq);
		(void) sqlite3_bind_text(stmt, 4, url->host, strlen(url->host), NULL);
		(void) sqlite3_bind_text(stmt, 5, url->args, strlen(url->args), NULL);
		do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return sqlx_transaction_end(repctx, err);
}


static GError *
__get_all_services(struct sqlx_sqlite3_s *sq3, struct meta1_service_url_s ***result)
{
    GError *err = NULL;
    sqlite3_stmt *stmt = NULL;
    GPtrArray *gpa;
    int rc;

    // Prepare the statement
    sqlite3_prepare_debug(rc, sq3->db,
            "SELECT DISTINCT srvtype,url FROM services order by srvtype,url", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return M1_SQLITE_GERROR(sq3->db, rc);

    // Run the result
    gpa = g_ptr_array_new();
    while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
            struct meta1_service_url_s *u;

            u = g_malloc0(sizeof(struct meta1_service_url_s) + 1 + sqlite3_column_bytes(stmt, 3));
            u->seq = 0;
            g_strlcpy(u->srvtype, (gchar*)sqlite3_column_text(stmt, 0), sizeof(u->srvtype));
            g_strlcpy(u->host,    (gchar*)sqlite3_column_text(stmt, 1), sizeof(u->host)-1);
            u->args[0] = '\0';
            g_ptr_array_add(gpa, u);
    }

    if (rc != SQLITE_DONE && rc != SQLITE_OK)
        err = M1_SQLITE_GERROR(sq3->db, rc);

    sqlite3_finalize_debug(rc, stmt);

    if (err) {
        gpa_str_free(gpa);
        return err;
    }

    g_ptr_array_add(gpa, NULL);
    *result = (struct meta1_service_url_s**) g_ptr_array_free(gpa, FALSE);
    return NULL;
}



static GError *
__get_container_all_services(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		const gchar *srvtype, struct meta1_service_url_s ***result)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GPtrArray *gpa;
	int rc;

	/* Prepare the statement */
	if (srvtype && *srvtype) {
		sqlite3_prepare_debug(rc, sq3->db,
				"SELECT seq,srvtype,url,args FROM services WHERE cid = ? AND srvtype = ?", -1, &stmt, NULL);
		if (rc != SQLITE_OK)
			return M1_SQLITE_GERROR(sq3->db, rc);
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, strlen(srvtype), NULL);
	}
	else {
		sqlite3_prepare_debug(rc, sq3->db,
				"SELECT seq,srvtype,url,args FROM services WHERE cid = ?", -1, &stmt, NULL);
		if (rc != SQLITE_OK)
			return M1_SQLITE_GERROR(sq3->db, rc);
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
	}

	/* Run the result */
	gpa = g_ptr_array_new();
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			struct meta1_service_url_s *u;

			u = g_malloc0(sizeof(struct meta1_service_url_s) + 1 + sqlite3_column_bytes(stmt, 3));
			u->seq = sqlite3_column_int(stmt, 0);
			g_strlcpy(u->srvtype, (gchar*)sqlite3_column_text(stmt, 1), sizeof(u->srvtype));
			g_strlcpy(u->host, (gchar*)sqlite3_column_text(stmt, 2), sizeof(u->host)-1);
			memcpy(u->args, (gchar*)sqlite3_column_text(stmt, 3), sqlite3_column_bytes(stmt, 3));
			g_ptr_array_add(gpa, u);
	}

	if (rc != SQLITE_DONE && rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);

	sqlite3_finalize_debug(rc, stmt);

	if (err) {
		gpa_str_free(gpa);
		return err;
	}

	g_ptr_array_add(gpa, NULL);
	*result = (struct meta1_service_url_s**) g_ptr_array_free(gpa, FALSE);
	return NULL;
}

static GError *
__save_service(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		struct meta1_service_url_s *url)
{
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db,
			"INSERT OR REPLACE INTO services (cid,srvtype,seq,url,args)"
			" VALUES (?,?,?,?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
	(void) sqlite3_bind_text(stmt, 2, url->srvtype, -1, NULL);
	(void) sqlite3_bind_int(stmt,  3, url->seq);
	(void) sqlite3_bind_text(stmt, 4, url->host, -1, NULL);
	(void) sqlite3_bind_text(stmt, 5, url->args, -1, NULL);
	do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
	if (rc != SQLITE_DONE && rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	return err;
}

static GError *
__delete_service(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		const gchar *srvtype)
{
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db,
			"DELETE FROM services WHERE cid = ? AND srvtype = ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
	(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
	do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);
	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}
	sqlite3_finalize_debug(rc, stmt);

	return err;
}

//------------------------------------------------------------------------------

static gboolean
_filter_tag(struct service_info_s *si, gpointer u)
{
	struct compound_type_s *ct = u;

	g_assert(ct != NULL);
	if (!ct->req.k)
		return TRUE;

	struct service_tag_s *tag = service_info_get_tag(si->tags, ct->req.k);
	if (NULL == tag)
		return FALSE;

	switch (tag->type) {
		case STVT_BUF:
			return !fnmatch(ct->req.v, tag->value.buf, 0);
		case STVT_STR:
			return !fnmatch(ct->req.v, tag->value.s, 0);
		default:
			return FALSE;
	}
}

static GError*
_get_iterator(struct meta1_backend_s *m1, struct compound_type_s *ct,
		struct grid_lb_iterator_s **result)
{
	struct grid_lb_iterator_s *r = grid_lbpool_get_iterator(m1->lb, ct->baretype);

	if (!r) {
		*result = NULL;
		return NEWERROR(460, "type [%s] not managed", ct->baretype);
	}

	*result = grid_lb_iterator_share(r);
	return NULL;
}

static GError*
_get_iterator2(struct meta1_backend_s *m1, const gchar *srvtype,
		struct grid_lb_iterator_s **result)
{
	struct compound_type_s ct;
	GError *err;

	*result = NULL;
	memset(&ct, 0, sizeof(ct));

	err = compound_type_parse(&ct, srvtype);
	if (NULL != err) {
		g_prefix_error(&err, "Type parsing error: ");
		return err;
	}

	err = _get_iterator(m1, &ct, result);
	if (err)
		g_prefix_error(&err, "LB error: ");
	compound_type_clean(&ct);
	return err;
}

static GSList *
__srvinfo_from_m1srvurl(struct grid_lbpool_s *glp, const gchar *type,
		struct meta1_service_url_s **urls)
{
	GSList *out = NULL;
	struct service_info_s* srvinfo = NULL;
	struct meta1_service_url_s **cursor = NULL;
	for (cursor = urls; cursor && *cursor; cursor++) {
		srvinfo = grid_lbpool_get_service_from_url(glp, type, (*cursor)->host);
		out = g_slist_prepend(out, srvinfo);
	}
	return out;
}

static struct meta1_service_url_s *
__poll_services(struct meta1_backend_s *m1, guint replicas,
		struct compound_type_s *ct, guint seq,
		struct meta1_service_url_s **used, GError **err)
{
	struct grid_lb_iterator_s *iter = NULL;
	struct service_info_s **siv = NULL;

	GRID_DEBUG("Polling %u [%s]", replicas, ct->fulltype);

	if (!(*err = _get_iterator(m1, ct, &iter))) {
		struct lb_next_opt_ext_s opt;
		memset(&opt, 0, sizeof(opt));
		opt.req.distance = MACRO_COND(replicas>1,1,0);
		opt.req.max = replicas;
		opt.req.duplicates = FALSE;
		opt.req.stgclass = NULL;
		opt.req.strict_stgclass = TRUE;
		opt.srv_forbidden = __srvinfo_from_m1srvurl(m1->lb, ct->baretype, used);
		opt.filter.hook = _filter_tag;
		opt.filter.data = ct;

		if (!grid_lb_iterator_next_set2(iter, &siv, &opt)) {
			g_assert(siv == NULL);
			*err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No service available");
		}

		grid_lb_iterator_clean(iter);
		iter = NULL;
		g_slist_free_full(opt.srv_forbidden, (GDestroyNotify)service_info_clean);
	}

	if(NULL != *err)
		return NULL;

	GString *compound_url = g_string_new("");

	for (struct service_info_s **p=siv; *p ; p++) {
		gchar str[STRLEN_ADDRINFO];
		grid_addrinfo_to_string(&((*p)->addr), str, sizeof(str));
		if (compound_url->len > 0)
			g_string_append_c(compound_url, ',');
		g_string_append(compound_url, str);
	}
	service_info_cleanv(siv, FALSE);
	siv = NULL;

	struct meta1_service_url_s *url = g_malloc0(sizeof(*url));
	g_strlcpy(url->srvtype, ct->type, sizeof(url->srvtype));
	g_strlcpy(url->host, compound_url->str, sizeof(url->host));
	url->seq = seq;
	g_string_free(compound_url, TRUE);
	return url;
}

static struct meta1_service_url_s **
__get_services_up(struct meta1_backend_s *m1, struct meta1_service_url_s **src)
{
	struct grid_lb_iterator_s *iter = NULL;

	if (!src || !*src)
		return NULL;

	GError *err = _get_iterator2(m1, (*src)->srvtype, &iter);
	if (NULL != err) {
		GRID_WARN("No iterator available on type [%s] : (%d) %s",
				(*src)->srvtype, err->code, err->message);
		g_clear_error(&err);
		return NULL;
	}

	GPtrArray *gpa = g_ptr_array_new();
	for (; *src ;src++) {
		gboolean one_is_up = FALSE;
		struct meta1_service_url_s **pe, **extracted;

		// This converts a compound (comma-separated) URL into an array
		// of unitary URLs. Each unitary URL is checked as is.
		extracted = expand_url(*src);
		for (pe=extracted; !one_is_up && *pe ;pe++)
			one_is_up = grid_lb_iterator_is_url_available(iter, (*pe)->host);
		if (one_is_up) {
			for (pe=extracted; *pe ;pe++)
				g_ptr_array_add(gpa, meta1_url_dup(*pe));
		}

		free_urlv(extracted);
		extracted = NULL;
	}

	grid_lb_iterator_clean(iter);
	iter = NULL;

	if (gpa->len <= 0) {
		g_ptr_array_free(gpa, TRUE);
		return NULL;
	}

	g_ptr_array_add(gpa, NULL);
	return (struct meta1_service_url_s**) g_ptr_array_free(gpa, FALSE);
}

static GError *
__get_container_service2(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, struct compound_type_s *ct,
		struct meta1_backend_s *m1, gchar ***result,
		enum m1v2_getsrv_e mode)
{
	GError *err = NULL;
	struct meta1_service_url_s **used = NULL;
	enum service_update_policy_e policy;
	guint replicas;

	struct service_update_policies_s *pol;
	if (!(pol = _policies(m1, hc_url_get(url, HCURL_NS))))
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Bad NS/Policy pair");
	policy = service_howto_update(pol, ct->baretype);
	replicas = service_howmany_replicas(pol, ct->baretype);
	replicas = (replicas > 0 ? replicas : 1);
	// Patches the constraint on the service type (if not set in the request)
	// by the constraint set in the NS-wide storage policy.
	compound_type_update_arg(ct, pol, FALSE);

	err = __get_container_all_services(sq3, hc_url_get_id(url), ct->type, &used);
	if (NULL != err) {
		g_prefix_error(&err, "Preliminary lookup error : ");
		return err;
	}
	if (used && !*used) {
		g_free(used);
		used = NULL;
	}

	if ((mode & M1V2_GETSRV_REUSE) && used) { /* Only keep the services UP */
		struct meta1_service_url_s **up = __get_services_up(m1, used);
		if (up && *up) {
			*result = pack_urlv(up);
			free_urlv(up);
			free_urlv(used);
			return NULL;
		}
		free_urlv(up);
	}

	/* No service available, poll a new one */
	if ((mode & M1V2_GETSRV_REUSE) && used &&
			(policy == SVCUPD_NONE || policy == SVCUPD_NOT_SPECIFIED))
		*result = pack_urlv(used);
	else {
		gint seq;
		struct meta1_service_url_s *m1_url = NULL;

		seq = urlv_get_max_seq(used);
		seq = (seq<0 ? 1 : seq+1);

		if (NULL != (m1_url = __poll_services(m1, replicas, ct, seq,
				used, &err))) {
			if (!(mode & M1V2_GETSRV_DRYRUN)) {
				struct sqlx_repctx_s *repctx = NULL;
				err = sqlx_transaction_begin(sq3, &repctx);
				if (NULL == err) {
					if (policy == SVCUPD_REPLACE)
						err = __delete_service(sq3, hc_url_get_id(url), ct->type);
					if (NULL == err)
						err = __save_service(sq3, hc_url_get_id(url), m1_url);
					err = sqlx_transaction_end(repctx, err);
				}
			}

			if (!err && result) {
				struct meta1_service_url_s **unpacked = expand_url(m1_url);
				*result = pack_urlv(unpacked);
				free_urlv(unpacked);
			}
			g_free(m1_url);
		}
	}

	free_urlv(used);
	return err;
}

static GError *
__get_container_service(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype,
		struct meta1_backend_s *m1, gchar ***result,
		enum m1v2_getsrv_e mode)
{
	GError *err = NULL;
	struct compound_type_s ct;

	if (NULL != (err = compound_type_parse(&ct, srvtype)))
		return err;
	err = __get_container_service2(sq3, url, &ct, m1, result, mode);
	compound_type_clean(&ct);
	return err;
}

static GError *
__reuse_container_service(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype,
		struct meta1_backend_s *m1, gboolean dryrun, gchar ***result)
{
	enum m1v2_getsrv_e mode = M1V2_GETSRV_REUSE|(dryrun? M1V2_GETSRV_DRYRUN:0);
	return __get_container_service(sq3, url, srvtype, m1, result, mode);
}

static GError *
__renew_container_service(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype,
		struct meta1_backend_s *m1, gboolean dryrun, gchar ***result)
{
	enum m1v2_getsrv_e mode = M1V2_GETSRV_RENEW|(dryrun? M1V2_GETSRV_DRYRUN:0);
	return __get_container_service(sq3, url, srvtype, m1, result, mode);
}



/* ------------------------------------------------------------------------- */

GError*
meta1_backend_set_service_arguments(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *packedurl)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s *url;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(packedurl != NULL);

	if (!(url = meta1_unpack_url(packedurl)))
		return NEWERROR(400, "Invalid URL");

	GRID_DEBUG("About to reconfigure [%s] [%"G_GINT64_FORMAT"] [%s] [%s]",
			url->srvtype, url->seq, url->host, url->args);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __configure_service(sq3, cid, url);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	g_free(url);

	return err;
}

GError*
meta1_backend_force_service(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *packedurl)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s *url;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(packedurl != NULL);

	if (!(url = meta1_unpack_url(packedurl)))
		return NEWERROR(400, "Invalid URL");

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __insert_service(sq3, cid, url);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	g_free(url);

	return err;
}



GError *
meta1_backend_get_all_services(struct meta1_backend_s *m1, const container_id_t cid, gchar ***result)
{
    GError *err = NULL;
    struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s **used = NULL;

    EXTRA_ASSERT(m1 != NULL);
    EXTRA_ASSERT(cid != NULL);

    err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERSLAVE, &sq3);
    if (!err) {
		err = __get_all_services(sq3, &used);
        if (NULL != err)
			g_prefix_error(&err, "Query error: ");
		else {
                struct meta1_service_url_s **expanded;
                expanded = expand_urlv(used);
                *result = pack_urlv(expanded);
                free_urlv(expanded);
                free_urlv(used); 			
		}

        sqlx_repository_unlock_and_close_noerror(sq3);
    }

    return err;
}



GError *
meta1_backend_get_container_service_available(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype, gboolean dryrun,
		gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);

	err = _open_and_lock(m1, hc_url_get_id(url), M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, hc_url_get_id(url), NULL))) {
			err = __reuse_container_service(sq3, url, srvtype, m1, dryrun,
					result);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta1_backend_get_container_new_service(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype, gboolean dryrun,
		gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(result != NULL);

	err = _open_and_lock(m1, hc_url_get_id(url), M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, hc_url_get_id(url), NULL))) {
			err = __renew_container_service(sq3, url, srvtype, m1, dryrun,
					result);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_get_container_all_services(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			struct meta1_service_url_s **uv = NULL;
			err = __get_container_all_services(sq3, cid, srvtype, &uv);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
			else {
				struct meta1_service_url_s **expanded;
				expanded = expand_urlv(uv);
				*result = pack_urlv(expanded);
				free_urlv(expanded);
				free_urlv(uv);
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta1_backend_del_container_services(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, gchar **urlv)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			//delete container services
			err = __del_container_services(sq3, cid, srvtype, urlv);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

/* ------------------------------------------------------------------------- */

static GError *
__destroy_on_meta2(struct meta1_service_url_s *url, const container_id_t cid)
{
	struct addr_info_s m2addr;
	GError *err = NULL;

	GRID_DEBUG("Destruction attempt on META2 at [%s]", url->host);

	if (!meta1_url_get_address(url, &m2addr))
		return NEWERROR(500, "Invalid address [%s] (%d %s)",
				url->host, errno, strerror(errno));

	if (!meta2_remote_container_destroy(&m2addr, 30000, &err, cid)) {
		if (!err)
			return NEWERROR(502, "Unknown error when contacting META2");
		g_prefix_error(&err, "META2 error : ");
		return err;
	}

	return NULL;
}

static GError*
_get_expanded(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		const gchar *srvtype, struct meta1_service_url_s ***result)
{
	struct meta1_service_url_s **services = NULL;
	GError *err = __get_container_all_services(sq3, cid, srvtype, &services);
	if (NULL != err)
		return err;
	*result = expand_urlv(services);
	if (services)
		free_urlv(services);
	return NULL;
}

static void
__del_container_meta2_noerror(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid)
{
	GError *err = __del_container_services(sq3, cid, "meta2", NULL);
	if (NULL != err) {
		GRID_WARN("Failed to delete meta2 service links : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
}

static void
__destroy_container_noerror(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid)
{
	gboolean done = FALSE;
	GError *err = __destroy_container(sq3, cid, FALSE, &done);
	if (NULL != err) {
		GRID_WARN("Failed to destroy the container reference : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
}

GError*
meta1_backend_destroy_m2_container(struct meta1_backend_s *m1,
		const container_id_t cid)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s **services = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (NULL != err)
		return err;

	if (!(err = __info_container(sq3, cid, NULL))) {
		err = _get_expanded(sq3, cid, "meta2", &services);
		if (NULL != err)
			g_prefix_error(&err, "Query error: ");
	}
	if (!err) {
		if (services && *services) {
			for (struct meta1_service_url_s **p=services; !err && *p ;p++) {
				if (NULL != (err = __destroy_on_meta2(*p, cid)))
					break;
			}
			if (!err)
				__del_container_meta2_noerror(sq3, cid);
		}
		else // Not found
			err = NEWERROR(431, "No meta2 linked with this reference");

		if (!err)
			__destroy_container_noerror(sq3, cid);
	}

	if (services)
		meta1_service_url_vclean(services);

	sqlx_repository_unlock_and_close_noerror(sq3);

	return err;
}

/* ------------------------------------------------------------------------- */

struct meta1_full_service_url_s
{
	container_id_t cid;
	struct meta1_service_url_s *urls;
};

static void
free_full_urlv(struct meta1_full_service_url_s **uv)
{
	struct meta1_full_service_url_s **p;

	if (!uv)
		return;

	for (p=uv; *p ;p++) {
		if (*p) {
			g_free((*p)->urls);
			g_free(*p);
		}
	}

	g_free(uv);
}

static void
clean_hash(gpointer data)
{
	service_info_clean((struct service_info_s*) data);
}

static GError *
__get_services(struct sqlx_sqlite3_s *sq3, const gchar *excludeurl, const container_id_t cid,
		const gchar *srvtype, struct meta1_full_service_url_s ***result)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GPtrArray *gpa;
	int rc;
	gchar *t=NULL;
	guint excludeindex = 0;
	guint cidindex = 0;
	guint globindex=1;

	/* Prepare the statement */
	GString *sql = g_string_new("SELECT cid,seq,srvtype,url,args FROM services WHERE srvtype = ?");
	if (excludeurl && excludeurl[0]) {
		sql = g_string_append(sql, " AND url LIKE ?");
		globindex++;
		excludeindex = globindex;
	}
	if (cid ) {
		sql = g_string_append(sql, " AND cid = ?");
		globindex++;
		cidindex = globindex;
	}
	sqlite3_prepare_debug(rc, sq3->db,
			sql->str, -1, &stmt, NULL);

	g_string_free(sql, TRUE);

	(void) sqlite3_bind_text(stmt, 1, srvtype, strlen(srvtype), NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);
	if ( excludeurl && excludeurl[0]) {
		t =  g_strdup_printf("%%%s%%",excludeurl);
		(void) sqlite3_bind_text(stmt, excludeindex, t , strlen(t), NULL);
	}
	if ( cid ) {
		(void) sqlite3_bind_blob(stmt, cidindex, cid, sizeof(container_id_t), NULL);
	}

	/* Run the result */
	gpa = g_ptr_array_new();
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		struct meta1_full_service_url_s *u;
		struct meta1_service_url_s *urls;

		u = g_malloc0(sizeof(struct meta1_full_service_url_s));
		urls= g_malloc0(sizeof(struct meta1_service_url_s) + 1 + sqlite3_column_bytes(stmt, 3));
		memcpy(u->cid ,(guint8*)sqlite3_column_blob(stmt,0),sqlite3_column_bytes(stmt,0));
		urls->seq = sqlite3_column_int(stmt, 1);
		g_strlcpy(urls->srvtype, (gchar*)sqlite3_column_text(stmt, 2), sizeof(urls->srvtype));
		g_strlcpy(urls->host, (gchar*)sqlite3_column_text(stmt, 3), sizeof(urls->host)-1);
		memcpy(urls->args, (gchar*)sqlite3_column_text(stmt, 4), sqlite3_column_bytes(stmt, 4));
		u->urls = urls;
		g_ptr_array_add(gpa, u);
	}

	if (rc != SQLITE_DONE && rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);

	sqlite3_finalize_debug(rc, stmt);

	if (err) {
		gpa_str_free(gpa);
		return err;
	}

	g_ptr_array_add(gpa, NULL);
	*result = (struct meta1_full_service_url_s**) g_ptr_array_free(gpa, FALSE);

	return NULL;
}



static GHashTable*
_update_m1_policy_set_services_hash(const gchar *ns, const gchar *type,
		const gchar* tag_name, const gchar* tag_value, GError **err)
{
	GSList *list_srv = NULL;
	GHashTable *hash_srv2 = NULL;
	GError * localerr = NULL;

	list_srv = list_namespace_services(ns, type, &localerr);
	if ( list_srv) {
		hash_srv2=g_hash_table_new_full(g_str_hash,g_str_equal, g_free,clean_hash);
		GSList *lst=NULL;
		for (lst=list_srv; lst; lst = lst->next ) {
			gchar target[64];
			struct service_info_s *si = (struct service_info_s *)lst->data;
			addr_info_to_string(&(si->addr),target,sizeof(target));
			gboolean serviceavailable = TRUE;
			if ( tag_name && tag_name[0] ) {
				struct service_tag_s *tag=NULL;
				if (NULL !=  (tag = service_info_get_tag(si->tags, tag_name))) {
					switch (tag->type) {
						case STVT_BUF:
							serviceavailable = !fnmatch(tag_value, tag->value.buf, 0);
							break;
						case STVT_STR:
							serviceavailable = !fnmatch(tag_value, tag->value.s, 0);
							break;
						default:
							serviceavailable = FALSE;
					}
				}
			}
			g_hash_table_insert(hash_srv2,g_strdup(target),(serviceavailable ? si: NULL));
		}
		g_slist_free(list_srv);
	} else {
		if ( localerr )
			*err = localerr;
	}
	return hash_srv2;
}

static struct meta1_service_url_s *
__poll_services_with_contraints(struct meta1_backend_s *m1, guint replicas,
		guint reqdist, struct compound_type_s *ct, guint seq,
		addr_info_t *excludeservice, struct service_info_s **requestedsrv,
		const gchar *svc_args, GError **err)
{
	struct grid_lb_iterator_s *iter = NULL;
	struct service_info_s **siv = NULL;

	GRID_DEBUG("Polling %u [%s]", replicas, ct->fulltype);

	if (!(*err = _get_iterator(m1, ct, &iter))) {
		struct lb_next_opt_ext_s opt_ext;
		memset(&opt_ext, 0, sizeof(opt_ext));
		opt_ext.req.distance = reqdist;
		opt_ext.req.duplicates = FALSE;
		opt_ext.req.stgclass = NULL;
		opt_ext.req.strict_stgclass = TRUE;

		for (struct service_info_s **p = requestedsrv; p && *p; ++p)
			opt_ext.srv_inplace = g_slist_prepend(opt_ext.srv_inplace, *p);

		if (excludeservice != NULL) {
			struct service_info_s si;
			memset(&si, 0, sizeof(si));
			g_strlcpy(si.type, ct->baretype, sizeof(si.type));
			memcpy(&(si.addr), excludeservice, sizeof(struct addr_info_s));
			opt_ext.srv_forbidden = g_slist_prepend(NULL, &si);
		}

		opt_ext.req.max = replicas - g_slist_length(opt_ext.srv_inplace);

		GRID_DEBUG("Already in place: %d, excluded: %d",
				g_slist_length(opt_ext.srv_inplace),
				g_slist_length(opt_ext.srv_forbidden));

		if (!grid_lb_iterator_next_set2(iter, &siv, &opt_ext))
			*err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No service available");

		g_slist_free(opt_ext.srv_forbidden);
		g_slist_free(opt_ext.srv_inplace);
		opt_ext.srv_inplace = opt_ext.srv_forbidden = NULL;

		grid_lb_iterator_clean(iter);
		iter = NULL;
	}

	if (NULL != *err) {
		return NULL;
	}

	GString *compound_url = g_string_new("");

	for (struct service_info_s **p=siv; *p ; p++) {
		gchar str[STRLEN_ADDRINFO];
		grid_addrinfo_to_string(&((*p)->addr), str, sizeof(str));
		if (compound_url->len > 0)
			g_string_append_c(compound_url, ',');
		g_string_append(compound_url, str);
	}
	service_info_cleanv(siv, FALSE);
	siv = NULL;
	for (struct service_info_s **p=requestedsrv; *p ; p++) {
		gchar str[STRLEN_ADDRINFO];
		grid_addrinfo_to_string(&((*p)->addr), str, sizeof(str));
		if (compound_url->len > 0)
			g_string_append_c(compound_url, ',');
		g_string_append(compound_url, str);
	}

	// Last field already counts for 1 char, so strlen is ok
	struct meta1_service_url_s *url = g_malloc0(sizeof(*url) +
			(svc_args? strlen(svc_args) : 0));
	g_strlcpy(url->srvtype, ct->type, sizeof(url->srvtype));
	g_strlcpy(url->host, compound_url->str, sizeof(url->host));
	if (svc_args)
		g_strlcpy(url->args, svc_args, strlen(svc_args) + 1);
	url->seq = seq;
	g_string_free(compound_url, TRUE);
	return url;
}

static GError*
_update_m1_policy(struct meta1_backend_s *m1,
		struct meta1_full_service_url_s *m1_srv_urls,
		struct compound_type_s *ct, guint replica, guint reqdist, gchar *tag_name,
		const gchar *excludesrv, addr_info_t *excludeaddr,
		GHashTable *hash_srv, struct meta1_full_service_url_s **update_m1_srv_urls)
{
	GError *err = NULL;
	struct service_info_s **requestedsrv = NULL;
	gchar str_cid[STRLEN_CONTAINERID + 1];
	gchar *args = NULL;

	guint url_count = 0;
	args = g_strdup(m1_srv_urls->urls->args);
	struct meta1_service_url_s **m1_srv_url = expand_url(m1_srv_urls->urls);
	struct meta1_service_url_s **tmp;
	struct service_info_s *si = NULL;
	gboolean excludesrvfound = FALSE;

	memset(str_cid, '\0', sizeof(str_cid));
	container_id_to_string(m1_srv_urls->cid, str_cid, sizeof(str_cid));

	for (tmp = m1_srv_url; *tmp; tmp++) {
		//check tags
		url_count++;
		if (tag_name && tag_name[0]) {
			si = g_hash_table_lookup(hash_srv, (*tmp)->host);
			if (!si) {
				err = NEWERROR(481,
						"FAILED to update reference %s, missing or invalid "
						"tag %s in configured service %s",
						str_cid, tag_name, (*tmp)->host);
				goto failedend;
			}
		}
		if (excludesrv && excludesrv[0]) {
			if (g_strcmp0(excludesrv, (*tmp)->host) == 0) {
				excludesrvfound = TRUE;
			}
		}
	}
	//check replicas
	if (url_count == 1 && excludesrvfound) {
		err = NEWERROR(481,
				"FAILED to update reference %s, just one service configured, "
				"imposible to replace it", str_cid);
		goto failedend;
	}

	if (url_count > replica) {
		err = NEWERROR(481,
				"Failed to update Reference %s, Number of service %s [%d] "
				"greater than replicas [%d]",
				str_cid, ct->type, url_count, replica);
		goto failedend;
	}

	if (url_count == replica && !excludesrvfound)
		goto failedend;

	struct meta1_service_url_s *url = NULL;
	requestedsrv = convert_url_to_serviceinfo(m1_srv_urls->urls, excludesrv);
	if ((url = __poll_services_with_contraints(m1, replica, reqdist, ct,
				m1_srv_urls->urls->seq, excludeaddr, requestedsrv, args,
				&err))) {
		struct meta1_full_service_url_s *u;

		u = g_malloc0(sizeof(struct meta1_full_service_url_s));
		memcpy(u->cid, m1_srv_urls->cid, sizeof(container_id_t));
		u->urls = url;

		*update_m1_srv_urls = u;
	}

	if (requestedsrv && *requestedsrv)
		service_info_cleanv(requestedsrv,FALSE);
	requestedsrv = NULL;


failedend:
	if (args)
		g_free(args);
	free_urlv(m1_srv_url);

	return err;
}

static GError *
_update_m1_policy_by_prefix(struct meta1_backend_s *m1,
		gboolean isprefix, const container_id_t cid,
		struct compound_type_s *ct, guint replicas, guint reqdist,
		gchar *tag_name, const gchar *excludesrv, addr_info_t *excludeaddr,
		GHashTable *hash_srv, gboolean checkonly,
		gchar **result)
{
	GError *err = NULL;
	guint checkedRefCount = 0;
	guint failedRefCount = 0;
	guint updatedRefCount = 0;
	guint currentCount = 0;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct meta1_full_service_url_s **m1_srv_urls = NULL;

	void _commit_and_update_count(void)
	{
		err = sqlx_transaction_end(repctx, err);
		if (!err)
			updatedRefCount = updatedRefCount + currentCount;
		else
			failedRefCount = failedRefCount + currentCount;
		currentCount = 0;
		repctx = NULL;
	}

	if(NULL != (err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3)))
		return err;

	if(NULL != (err = __get_services(sq3, excludesrv, (isprefix? NULL : cid),
					ct->type, &m1_srv_urls)))
		goto failedend;

	struct meta1_full_service_url_s **items = m1_srv_urls;
	GError *localerr = NULL;

	for (; items && *items; items++) {
		checkedRefCount++;
		struct meta1_full_service_url_s *update_m1_srv_urls = NULL;

		if (localerr)
			g_clear_error(&localerr);

		if (NULL == repctx) {
			localerr = sqlx_transaction_begin(sq3, &repctx);
			if (NULL != localerr) {
				GRID_ERROR("M1 update policy failure (%d): %s", localerr->code, localerr->message);
				failedRefCount++;
				continue;
			}
		}

		localerr = _update_m1_policy(m1, *items, ct, replicas, reqdist, tag_name,
				excludesrv, excludeaddr, hash_srv, &update_m1_srv_urls);
		if (localerr) {
			GRID_ERROR("M1 update policy failure (%d): %s", localerr->code, localerr->message);
			failedRefCount++;
			continue;
		}

		if (update_m1_srv_urls) {
			currentCount ++;
			if (!checkonly) {
				err = __save_service(sq3, (*items)->cid, update_m1_srv_urls->urls);
			}
			g_free(update_m1_srv_urls->urls);
			g_free(update_m1_srv_urls);
			update_m1_srv_urls = NULL;
		}

		if ((checkedRefCount % 100 == 0) || (currentCount % 10 == 0) || err != NULL ) {
			_commit_and_update_count();
		}
	}

	if (repctx) {
		_commit_and_update_count();
	}

	if (!err) {
		*result = g_strdup_printf("%d|%d|%d", checkedRefCount,
				updatedRefCount, failedRefCount);
		/* take at least last biz error if no technical error */
		err = localerr;
	}


	free_full_urlv(m1_srv_urls);

failedend:

	sqlx_repository_unlock_and_close_noerror(sq3);

	return err;
}

GError*
meta1_backend_update_m1_policy(struct meta1_backend_s *m1, const gchar *ns,
		const container_id_t prefix, const container_id_t cid, const gchar *srvtype,
		const gchar *excludesrv, gchar *action, gboolean checkonly,
		gchar **result)
{
	GError *err = NULL;
	guint replicas = 1;
	guint reqdist = 1;
	gchar *tag_name = NULL, *tag_value = NULL;
	GHashTable *hash_srv = NULL;
	struct compound_type_s ct;
	addr_info_t *excludeaddr = NULL;
	struct service_update_policies_s *pol = _policies(m1, ns);

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	if (!pol)
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Bad NS/Policy pair");

	memset(&ct, 0, sizeof(struct compound_type_s));
	if (NULL != (err = compound_type_parse(&ct, srvtype)))
		goto failedend;

	replicas = service_howmany_replicas(pol, srvtype);
	replicas = (replicas > 0 ? replicas : 1);
	reqdist = service_howmany_distance(pol, srvtype);
	compound_type_update_arg(&ct, pol, TRUE);
	if (ct.req.k) {
		hash_srv =_update_m1_policy_set_services_hash(ns, srvtype, ct.req.k, ct.req.v, &err);
		if (err)
			goto failedend;
	}

	if ( g_strcmp0("EXCLUDE", action) == 0 && !excludesrv ) {
		err = NEWERROR(500,
				"Missing excluded service url, Madatory with EXCLUDE action");
		goto failedend;
	}

	if ( excludesrv && excludesrv[0]) {
		excludeaddr = g_malloc0(sizeof(addr_info_t));
		if ( !l4_address_init_with_url(excludeaddr,excludesrv,&err)) {
			GRID_WARN("Failed to build addr: %s", err->message);
			goto failedend;
		}
	}

	if ( cid ) {
		err = _update_m1_policy_by_prefix(m1, FALSE, cid, &ct, replicas, reqdist, tag_name,
				excludesrv, excludeaddr, hash_srv, checkonly, result);
	}
	else if ( prefix ) {
		err = _update_m1_policy_by_prefix(m1, TRUE, prefix, &ct, replicas, reqdist, tag_name,
				excludesrv, excludeaddr, hash_srv, checkonly, result);
	}
	else {
		err = NEWERROR(500, "Missing prefix or container parameter");
	}


failedend:
	if (tag_name)
		g_free(tag_name);
	if (tag_value)
		g_free(tag_value);
	if (hash_srv)
		g_hash_table_destroy(hash_srv);
	compound_type_clean(&ct);
	if (excludeaddr)
		addr_info_clean(excludeaddr);

	return  err;
}

