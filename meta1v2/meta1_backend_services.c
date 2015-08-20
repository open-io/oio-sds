/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

#include "./internals.h"
#include "./compound_types.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

static GError *__get_container_all_services(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype,
		struct meta1_service_url_s ***result);
static GError *__notify_services(struct meta1_backend_s *m1,
		struct sqlx_sqlite3_s *sq3, struct hc_url_s *url);
static GError *__notify_services_by_cid(struct meta1_backend_s *m1,
		struct sqlx_sqlite3_s *sq3, struct hc_url_s *url);

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

//------------------------------------------------------------------------------

static GError *
__del_container_srvtype_properties(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype)
{
   GError *err = NULL;
    gint rc;
    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_debug(rc, sq3->db,
        "DELETE FROM properties WHERE cid = ? AND name LIKE ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK && rc != SQLITE_DONE)
        err = M1_SQLITE_GERROR(sq3->db, rc);
    else {
        int len = strlen(srvtype)+10;
        gchar *tmp_name = g_malloc0(sizeof(gchar)*len);
		if (tmp_name) {
			g_snprintf(tmp_name, len, "%s.%%", srvtype);
			(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
			(void) sqlite3_bind_text(stmt, 2, tmp_name, -1, NULL);
			sqlite3_step_debug_until_end (rc, stmt);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = M1_SQLITE_GERROR(sq3->db, rc);
			sqlite3_finalize_debug(rc, stmt);
			g_free (tmp_name);
		}
	}

	return err;
}

static GError *
__del_container_all_services(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype)
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
		(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
		sqlite3_step_debug_until_end (rc, stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__del_container_one_service(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype, gint64 seq)
{
	static const gchar *sql = "DELETE FROM services WHERE cid = ? AND srvtype = ? AND seq = ?";
	sqlite3_stmt *stmt = NULL;
	GError *err = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
		(void) sqlite3_bind_int64(stmt, 3, seq);
		sqlite3_step_debug_until_end (rc, stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__del_container_services(struct meta1_backend_s *m1,
		struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const gchar *srvtype, gchar **urlv)
{
	gint64 seq;
	GError *err = NULL;
	guint line = 1;
	struct sqlx_repctx_s *repctx = NULL;

	if (NULL != (err = sqlx_transaction_begin(sq3, &repctx)))
		return err;

	if (!urlv || !*urlv)
		err = __del_container_all_services(sq3, url, srvtype);
	else {
		for (; !err && *urlv ;urlv++,line++) {
			gchar *end = NULL;

			errno = 0;
			seq = g_ascii_strtoll(*urlv, &end, 10);
			if ((end == *urlv) || (!seq && errno==EINVAL))
				err = NEWERROR(CODE_BAD_REQUEST, "line %u : Invalid number", line);
			else
				err = __del_container_one_service(sq3, url, srvtype, seq);
		}
	}

	// delete properties / services
	if (!err) {
		struct meta1_service_url_s **used = NULL;
		// list all services type of cid
		err = __get_container_all_services(sq3, url, srvtype, &used);
		if (err) {
			g_prefix_error(&err, "Preliminary lookup error : ");
		} else {
			if ((!used || !*used)){
				// service type not used for this container_id...
				// delete all properties about cid/srvtype
				__del_container_srvtype_properties(sq3, url, srvtype);
			}
		}
		meta1_service_url_cleanv (used);

		GError *err2 = __notify_services_by_cid(m1, sq3, url);
		if (err2 != NULL) {
			GRID_WARN("Failed to notify [%s] service deletions"
				" in [%s]: %s", srvtype, hc_url_get(url, HCURL_HEXID), err2->message);
			g_clear_error(&err2);
		}
	}

	return sqlx_transaction_end(repctx, err);
}

static GError *
__configure_service(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct meta1_service_url_s *m1url)
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
		(void) sqlite3_bind_text(stmt, 1, m1url->args, -1, NULL);
		(void) sqlite3_bind_blob(stmt, 2, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		(void) sqlite3_bind_int64(stmt, 3, m1url->seq);
		(void) sqlite3_bind_text(stmt, 4, m1url->srvtype, -1, NULL);
		sqlite3_step_debug_until_end (rc, stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
		if (!err && !sqlite3_changes(sq3->db))
			err = NEWERROR(CODE_SRV_NOLINK, "Service not found");
	}

	return sqlx_transaction_end(repctx, err);
}

static GError *
__get_all_services(struct sqlx_sqlite3_s *sq3,
		struct meta1_service_url_s ***result)
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
__get_container_all_services(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
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
		(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
	}
	else {
		sqlite3_prepare_debug(rc, sq3->db,
				"SELECT seq,srvtype,url,args FROM services WHERE cid = ?", -1, &stmt, NULL);
		if (rc != SQLITE_OK)
			return M1_SQLITE_GERROR(sq3->db, rc);
		(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
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
__save_service(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct meta1_service_url_s *m1url, gboolean force)
{
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db, force
			? "INSERT OR REPLACE INTO services (cid,srvtype,seq,url,args) VALUES (?,?,?,?,?)"
			: "INSERT            INTO services (cid,srvtype,seq,url,args) VALUES (?,?,?,?,?)",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
	(void) sqlite3_bind_text(stmt, 2, m1url->srvtype, -1, NULL);
	(void) sqlite3_bind_int(stmt,  3, m1url->seq);
	(void) sqlite3_bind_text(stmt, 4, m1url->host, -1, NULL);
	(void) sqlite3_bind_text(stmt, 5, m1url->args, -1, NULL);
	sqlite3_step_debug_until_end(rc, stmt);
	if (rc != SQLITE_DONE && rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	return err;
}

static GError *
__delete_service(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
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

	(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
	(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
	sqlite3_step_debug_until_end (rc, stmt);
	if (rc != SQLITE_DONE && rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	return err;
}

//------------------------------------------------------------------------------

static gboolean
_filter_tag(struct service_info_s *si, gpointer u)
{
	struct compound_type_s *ct = u;

	EXTRA_ASSERT(ct != NULL);
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
	struct grid_lb_iterator_s *r = grid_lbpool_get_iterator(m1->backend.lb,
			ct->baretype);

	if (!r) {
		*result = NULL;
		return NEWERROR(CODE_SRVTYPE_NOTMANAGED, "type [%s] not managed", ct->baretype);
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
		opt.srv_forbidden = __srvinfo_from_m1srvurl(m1->backend.lb,
				ct->baretype, used);
		opt.filter.hook = _filter_tag;
		opt.filter.data = ct;

		if (!grid_lb_iterator_next_set2(iter, &siv, &opt)) {
			EXTRA_ASSERT(siv == NULL);
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

		meta1_service_url_cleanv(extracted);
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
	if (!(pol = meta1_backend_get_svcupdate(m1)))
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Bad NS/Policy pair");
	policy = service_howto_update(pol, ct->baretype);
	replicas = service_howmany_replicas(pol, ct->baretype);
	replicas = (replicas > 0 ? replicas : 1);
	// Patches the constraint on the service type (if not set in the request)
	// by the constraint set in the NS-wide storage policy.
	compound_type_update_arg(ct, pol, FALSE);

	err = __get_container_all_services(sq3, url, ct->type, &used);
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
			meta1_service_url_cleanv(up);
			meta1_service_url_cleanv(used);
			return NULL;
		}
		meta1_service_url_cleanv(up);
	}

	/* No service available, poll a new one */
	if ((mode & M1V2_GETSRV_REUSE) && used &&
			(policy == SVCUPD_KEEP || policy == SVCUPD_NOT_SPECIFIED))
		*result = pack_urlv(used);
	else {
		gint seq;
		struct meta1_service_url_s *m1_url = NULL;

		seq = urlv_get_max_seq(used);
		seq = (seq<0 ? 1 : seq+1);

		if (NULL != (m1_url = __poll_services(m1, replicas, ct, seq, used, &err))) {
			if (!(mode & M1V2_GETSRV_DRYRUN)) {
				struct sqlx_repctx_s *repctx = NULL;
				err = sqlx_transaction_begin(sq3, &repctx);
				if (NULL == err) {
					if (policy == SVCUPD_REPLACE)
						err = __delete_service(sq3, url, ct->type);
					if (NULL == err)
						err = __save_service(sq3, url, m1_url, TRUE);
					err = sqlx_transaction_end(repctx, err);
				}
			}

			if (!err && result) {
				struct meta1_service_url_s **unpacked = expand_url(m1_url);
				*result = pack_urlv(unpacked);
				meta1_service_url_cleanv(unpacked);

				GError *err2 = __notify_services(m1, sq3, url);
				if (err2 != NULL) {
					GRID_WARN("Failed to notify [%s] service modifications"
							" of [%s]: %s", ct->type,
							hc_url_get(url, HCURL_WHOLE), err2->message);
					g_clear_error(&err2);
				}
			}
			g_free(m1_url);
		}
	}

	meta1_service_url_cleanv(used);
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
__renew_container_service(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar *srvtype,
		struct meta1_backend_s *m1, gboolean dryrun, gchar ***result)
{
	enum m1v2_getsrv_e mode = M1V2_GETSRV_RENEW|(dryrun? M1V2_GETSRV_DRYRUN:0);
	return __get_container_service(sq3, url, srvtype, m1, result, mode);
}

/* ------------------------------------------------------------------------- */

GError*
meta1_backend_services_config(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *packedurl)
{
	struct meta1_service_url_s *m1url;
	if (!(m1url = meta1_unpack_url(packedurl)))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid URL");

	GRID_DEBUG("About to reconfigure [%s] [%"G_GINT64_FORMAT"] [%s] [%s]",
			m1url->srvtype, m1url->seq, m1url->host, m1url->args);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			err = __configure_service(sq3, url, m1url);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
			else {
				GError *err2 = __notify_services_by_cid(m1, sq3, url);
				if (err2 != NULL) {
					GRID_WARN("Failed to notify [%s] service arg modification in [%s]: %s",
							m1url->srvtype, hc_url_get(url, HCURL_HEXID), err2->message);
					g_clear_error(&err2);
				}
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	g_free(m1url);
	return err;
}

GError*
meta1_backend_services_set(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *packedurl,
		gboolean autocreate, gboolean force)
{
	struct meta1_service_url_s *m1url;
	if (!(m1url = meta1_unpack_url(packedurl)))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid URL");

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			if (!(err = __info_user(sq3, url, autocreate, NULL)))
				err = __save_service(sq3, url, m1url, force);
			if (!(err = sqlx_transaction_end(repctx, err))) {
				GError *err2 = __notify_services_by_cid(m1, sq3, url);
				if (err2 != NULL) {
					GRID_WARN("Failed to notify forced service [%s] in [%s]:"
							" (%d) %s", packedurl, hc_url_get (url, HCURL_HEXID),
							err2->code, err2->message);
					g_clear_error(&err2);
				}
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	g_free(m1url);
	return err;
}

GError *
meta1_backend_services_all(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar ***result)
{
    struct sqlx_sqlite3_s *sq3 = NULL;
    GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
    if (!err) {
		struct meta1_service_url_s **used = NULL;
		if (NULL != (err = __get_all_services(sq3, &used)))
			g_prefix_error(&err, "Query error: ");
		else {
			struct meta1_service_url_s **expanded = expand_urlv(used);
			*result = pack_urlv(expanded);
			meta1_service_url_cleanv(expanded);
			meta1_service_url_cleanv(used); 			
		}

        sqlx_repository_unlock_and_close_noerror(sq3);
    }

    return err;
}

GError *
meta1_backend_services_link (struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype,
		gboolean dryrun, gboolean autocreate,
		gchar ***result)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_user(sq3, url, autocreate, NULL))) {
			enum m1v2_getsrv_e mode = M1V2_GETSRV_REUSE;
			if (dryrun) mode |= M1V2_GETSRV_DRYRUN;
			err = __get_container_service(sq3, url, srvtype, m1, result, mode);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta1_backend_services_poll(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype,
		gboolean dryrun, gboolean autocreate,
		gchar ***result)
{
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(result != NULL);
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_user(sq3, url, autocreate, NULL))) {
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
meta1_backend_services_list(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype, gchar ***result)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			struct meta1_service_url_s **uv = NULL;
			err = __get_container_all_services(sq3, url, srvtype, &uv);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
			else {
				struct meta1_service_url_s **expanded;
				expanded = expand_urlv(uv);
				*result = pack_urlv(expanded);
				meta1_service_url_cleanv(expanded);
				meta1_service_url_cleanv(uv);
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta1_backend_services_unlink(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype, gchar **urlv)
{
	EXTRA_ASSERT(srvtype != NULL);
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			err = __del_container_services(m1, sq3, url, srvtype, urlv);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

/* ------------------------------------------------------------------------- */

struct meta1_full_service_url_s
{
	container_id_t cid;
	struct meta1_service_url_s *urls;
};

static GError *
__notify_services_by_cid(struct meta1_backend_s *m1, struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url)
{
	struct hc_url_s **urls = NULL;
	GError *err = __info_user(sq3, url, FALSE, &urls);
	if (!err) {
		hc_url_set (urls[0], HCURL_NS, m1->backend.ns_name);
		err = __notify_services(m1, sq3, url);
	}
	hc_url_cleanv (urls);
	return err;
}

static GError *
__notify_services(struct meta1_backend_s *m1, struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url)
{
	if (!m1->notify.hook)
		return NULL;

	GError *err = NULL;
	struct meta1_service_url_s **services = NULL, **services2 = NULL;

	err = __get_container_all_services(sq3, url, NULL, &services);
	if (!err) {
		services2 = expand_urlv(services);
		GString *notif = g_string_sized_new(128);
		g_string_append (notif, "{\"event\":\""NAME_SRVTYPE_META1".account.services\"");
		g_string_append_printf (notif, ",\"when\":%"G_GINT64_FORMAT, g_get_real_time());
		g_string_append (notif, ",\"data\":{");
		g_string_append_printf (notif, "\"url\":\"%s\"", hc_url_get(url, HCURL_WHOLE));
		g_string_append (notif, ",\"services\":[");
		for (struct meta1_service_url_s **svc = services2; svc && *svc; svc++) {
			if (svc != services2) // not at the beginning
				g_string_append(notif, ",");
			meta1_service_url_encode_json(notif, *svc);
		}
		g_string_append(notif, "]}}");

		m1->notify.hook (m1->notify.udata, g_string_free(notif, FALSE));

		meta1_service_url_cleanv(services2);
		meta1_service_url_cleanv(services);
	}
	return err;
}

GError *
meta1_backend_notify_services(struct meta1_backend_s *m1, struct hc_url_s *url)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		err = __notify_services(m1, sq3, url);
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
	return err;
}

