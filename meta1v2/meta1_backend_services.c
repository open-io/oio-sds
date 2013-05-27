/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.backend"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fnmatch.h>

#include <glib.h>
#include <sqlite3.h>

#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/resolv.h"
#include "../metautils/lib/lb.h"
#include "../metautils/lib/svc_policy.h"
#include "../sqliterepo/sqliterepo.h"
#include "../meta2/remote/meta2_remote.h"

#include "./internals.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

struct iterator_args_s {
	gchar *tag;
	gchar *value;
};

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
	if (uv) { for (; *uv ;++uv) {
		struct meta1_service_url_s **p, **utmp;
		if (NULL != (utmp = expand_url(*uv))) {
			for (p=utmp; *p ;++p)
				g_ptr_array_add(tmp, *p);
			g_free(utmp);
		}
	} }

	g_ptr_array_add(tmp, NULL);
	return (struct meta1_service_url_s**)g_ptr_array_free(tmp, FALSE);
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
	struct sqlx_repctx_s *repctx;

	repctx = sqlx_transaction_begin(sq3);

	if (!urlv || !*urlv)
		err = __del_container_all_services(sq3, cid, srvtype);
	else {
		for (; !err && *urlv ;urlv++,line++) {
			gchar *end = NULL;

			errno = 0;
			seq = g_ascii_strtoll(*urlv, &end, 10);
			if ((end == *urlv) || (!seq && errno==EINVAL))
				err = g_error_new(m1b_gquark_log, 400, "line %u : Invalid number", line);
			else
				err = __del_container_one_service(sq3, cid, srvtype, seq);
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
	struct sqlx_repctx_s *repctx;

	repctx = sqlx_transaction_begin(sq3);

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
			err = g_error_new(m1b_gquark_log, 450, "Service not found");
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

	repctx = sqlx_transaction_begin(sq3);

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
			"INSERT INTO services (cid,srvtype,seq,url,args)"
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

static gboolean
tag_filter(struct service_info_s *si, gpointer hook_data)
{
	struct iterator_args_s* it_tag = (struct iterator_args_s*)hook_data;
	struct service_tag_s *tag;

	if (!(tag = service_info_get_tag(si->tags, it_tag->tag)))
		return FALSE;

	switch (tag->type) {
		case STVT_BUF:
			return !fnmatch(it_tag->value, tag->value.buf, 0);
		case STVT_STR:
			return !fnmatch(it_tag->value, tag->value.s, 0);
		default:
			return FALSE;
	}
}

static void
cleanup_iterator_args(gpointer p) // GDestroyNotify
{
	struct iterator_args_s *it;
	if (!(it = p))
		return;
	if (it->value)
		g_free(it->value);
	if (it->tag)
		g_free(it->tag);
	g_free(p);
}

struct compound_type_s
{
	const gchar *fulltype;
	gchar *baretype;
	gchar *subtype;
	gchar *type; // baretype . subtype
	gchar *args;
};

static void
_clean_compound_type(struct compound_type_s *ct)
{
	if (!ct)
		return;
	if (ct->type)
		g_free(ct->type);
	if (ct->args)
		g_free(ct->args);
	if (ct->baretype)
		g_free(ct->baretype);
	if (ct->subtype)
		g_free(ct->subtype);
}

static GError*
_parse_compound_type(struct compound_type_s *ct, const gchar *srvtype)
{
	gchar** srvtype_tokens, **type_tokens;

	g_assert(ct != NULL);

	if (!srvtype || !*srvtype || *srvtype == '.' || *srvtype == ';')
		return NEWERROR(400, "Bad service type [%s]", srvtype);

	// TYPE[.SUBTYPE][;ARGS]
	ct->fulltype = srvtype;

	srvtype_tokens = g_strsplit(srvtype, ";", 2);
	ct->type = srvtype_tokens[0];
	ct->args = srvtype_tokens[1] ? srvtype_tokens[1] : g_strdup("");
	g_free(srvtype_tokens);

	type_tokens = g_strsplit(ct->type, ".", 2);
	ct->baretype = type_tokens[0];
	ct->subtype = type_tokens[1] ? type_tokens[1] : g_strdup("");
	g_free(type_tokens);

	GRID_TRACE("CT full[%s] type[%s] args[%s] bare[%s] sub[%s]",
			ct->fulltype, ct->type, ct->args, ct->baretype, ct->subtype);

	return NULL;
}

static GError*
_get_iterator(struct meta1_backend_s *m1, struct compound_type_s *ct,
		struct grid_lb_iterator_s **result)
{
	struct grid_lb_iterator_s *temp_result = NULL;
	hashstr_t *htype = NULL;
	GError *err = NULL;

	HASHSTR_ALLOCA(htype, ct->baretype);

	if (!(temp_result = g_tree_lookup(m1->tree_lb, htype)))
		err = NEWERROR(460, "type [%s] not managed", hashstr_str(htype));
	else if (!ct->args || !ct->args[0] || ct->args[0] == '=') {
		// We create a sub-iterator without filter
		*result = grid_lb_iterator_share(temp_result, NULL, NULL, NULL);
	}
	else {
		// We create a sub-iterator with a filter
		gchar** tag_tokens = g_strsplit(ct->args, "=", 2);
		if (!tag_tokens[0])
			err = NEWERROR(400, "Bad tag format");
		else if (!tag_tokens[1])
			*result = grid_lb_iterator_share(temp_result, NULL, NULL, NULL);
		else {
			struct iterator_args_s *args = (struct iterator_args_s *)g_malloc0(sizeof(struct iterator_args_s));
			args->tag = tag_tokens[0];
			args->value = tag_tokens[1];
			g_free(tag_tokens);
			tag_tokens = NULL;
			*result = grid_lb_iterator_share(temp_result, &tag_filter, args, cleanup_iterator_args);
		}
		if (tag_tokens)
			g_strfreev(tag_tokens);
	}

	return err;
}

static struct meta1_service_url_s *
__poll_services(struct meta1_backend_s *m1, guint replicas,
		struct compound_type_s *ct, guint seq)
{
	struct grid_lb_iterator_s *iter = NULL;
	struct service_info_s **siv = NULL;
	GError *err = NULL;

	struct lb_next_opt_s opt;
	opt.dupplicates = FALSE;
	opt.max = replicas;
	opt.reqdist = 0;

	GRID_DEBUG("Polling %u [%s]", replicas, ct->fulltype);

	g_mutex_lock(m1->lock); /* XXX lock */
	if (!(err = _get_iterator(m1, ct, &iter))) {
		if (replicas <= 1) {
			struct service_info_s *si = NULL;
			if (!grid_lb_iterator_next(iter, &si, 300)) {
				g_assert(si == NULL);
				err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No service available");
			}
			else {
				siv = g_malloc0(2 * sizeof(void*));
				siv[0] = si;
				si = NULL;
			}
		}
		else {
			if (!grid_lb_iterator_next_set(iter, &siv, &opt)) {
				g_assert(siv == NULL);
				err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No service available");
			}
		}
		grid_lb_iterator_clean(iter);
		iter = NULL;
	}
	g_mutex_unlock(m1->lock); /* XXX unlock */

	if (err) {
		GRID_DEBUG("Unexpected service type [%s] : (%d) %s", ct->fulltype, err->code, err->message);
		g_clear_error(&err);
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
	struct compound_type_s ct;
	GError *err = NULL;
	struct grid_lb_iterator_s *iter = NULL;
	GPtrArray *gpa;

	if (!src || !*src)
		return NULL;

	memset(&ct, 0, sizeof(struct compound_type_s));
	if (NULL != (err = _parse_compound_type(&ct, (*src)->srvtype))) {
		GRID_DEBUG("Unexpected service type [%s] : (%d) %s", (*src)->srvtype, err->code, err->message);
		g_clear_error(&err);
		return NULL;
	}

	gpa = g_ptr_array_new();

	g_mutex_lock(m1->lock); /* XXX lock */
	if (!(err = _get_iterator(m1, &ct, &iter))) {
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
	}
	g_mutex_unlock(m1->lock); /* XXX unlock */

	if (err) {
		GRID_INFO("No iterator found for type [%s] : (%d) %s", ct.fulltype, err->code, err->message);
		g_clear_error(&err);
	}
	_clean_compound_type(&ct);

	if (gpa->len <= 0) {
		g_ptr_array_free(gpa, TRUE);
		return NULL;
	}

	g_ptr_array_add(gpa, NULL);
	return (struct meta1_service_url_s**) g_ptr_array_free(gpa, FALSE);
}

static GError *
__get_container_service2(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, struct compound_type_s *ct,
		struct meta1_backend_s *m1, gchar ***result,
		gboolean reuse)
{
	GError *err = NULL;
	struct meta1_service_url_s **used = NULL;
	enum service_update_policy_e policy;
	guint replicas;

	policy = service_howto_update(m1->policies, ct->baretype);
	replicas = service_howmany_replicas(m1->policies, ct->baretype);
	replicas = (replicas > 0 ? replicas : 1);
	if (!ct->args || !ct->args[0]) {
		gchar *n=NULL, *v=NULL;
		if (service_update_tagfilter(m1->policies, ct->baretype, &n, &v)) {
				if (ct->args)
					g_free(ct->args);
				ct->args = g_strconcat(n, "=", v, NULL);
		}
		if (n)
			g_free(n);
		if (v)
			g_free(v);
	}

	if (NULL != (err = __get_container_all_services(sq3, cid, ct->type, &used))) {
		g_prefix_error(&err, "Preliminary lookup error : ");
		return err;
	}
	if (used && !*used) {
		g_free(used);
		used = NULL;
	}

	if (reuse && used) { /* Only keep the services UP */
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
	if (reuse && used && (policy == SVCUPD_NONE || policy == SVCUPD_NOT_SPECIFIED))
		*result = pack_urlv(used);
	else {
		gint seq;
		struct meta1_service_url_s *url = NULL;

		seq = urlv_get_max_seq(used);
		seq = (seq<0 ? 1 : seq+1);

		if (!(url = __poll_services(m1, replicas, ct, seq)))
			err = g_error_new(m1b_gquark_log, 461, "no service available");
		else {
			struct sqlx_repctx_s *repctx = sqlx_transaction_begin(sq3);
			if (policy == SVCUPD_REPLACE)
				err = __delete_service(sq3, cid, ct->type);
			if (!err)
				err = __save_service(sq3, cid, url);
			err = sqlx_transaction_end(repctx, err);

			if (!err && result) {
				struct meta1_service_url_s **unpacked = expand_url(url);
				*result = pack_urlv(unpacked);
				free_urlv(unpacked);
			}
			g_free(url);
		}
	}

	free_urlv(used);
	return err;
}

static GError *
__get_container_service(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, const gchar *srvtype,
		struct meta1_backend_s *m1, gchar ***result,
		gboolean reuse)
{
	GError *err = NULL;
	struct compound_type_s ct;

	memset(&ct, 0, sizeof(struct compound_type_s));
	if (NULL != (err = _parse_compound_type(&ct, srvtype)))
		return err;
	err = __get_container_service2(sq3, cid, &ct, m1, result, reuse);
	_clean_compound_type(&ct);

	return err;
}

/* ------------------------------------------------------------------------- */

GError*
meta1_backend_set_service_arguments(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *packedurl)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s *url;

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);
	META1_ASSERT(packedurl != NULL);

	if (!(url = meta1_unpack_url(packedurl)))
		return g_error_new(m1b_gquark_log, 400, "Invalid URL");

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

	return err;
}

GError*
meta1_backend_force_service(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *packedurl)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s *url;

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);
	META1_ASSERT(packedurl != NULL);

	if (!(url = meta1_unpack_url(packedurl)))
		return g_error_new(m1b_gquark_log, 400, "Invalid URL");

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __insert_service(sq3, cid, url);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_get_container_service_available(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __get_container_service(sq3, cid, srvtype, m1, result, TRUE);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta1_backend_get_container_new_service(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);
	META1_ASSERT(srvtype != NULL);
	META1_ASSERT(result != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __get_container_service(sq3, cid, srvtype, m1, result, FALSE);
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

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);

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
				free_urlv(uv);
				free_urlv(expanded);
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

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);
	META1_ASSERT(srvtype != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
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
		return g_error_new(m1b_gquark_log, 500, "Invalid address [%s] (%d %s)",
				url->host, errno, strerror(errno));

	if (!meta2_remote_container_destroy(&m2addr, 30000, &err, cid)) {
		if (!err)
			return g_error_new(m1b_gquark_log, 502,
					"Unknown error when contacting META2");
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

GError*
meta1_backend_destroy_m2_container(struct meta1_backend_s *m1,
		const container_id_t cid)
{
	GError *err = NULL;
	GError *tmp = NULL;
	gboolean done = FALSE;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct meta1_service_url_s **services = NULL;

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(cid != NULL);

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
			struct meta1_service_url_s **p;

			for (p=services; !err && *p ;p++) {
				if (NULL != (err = __destroy_on_meta2(*p, cid)))
					break;
			}

			if (!err) {
				/* try to delete the link service, don't take care of the error */
				tmp = __del_container_services(sq3, cid, "meta2", NULL);
				if (NULL != tmp)
					g_clear_error(&tmp);
				//	g_prefix_error(&err, "Query error: ");
			}
		}
		else {
			/* Container Not Found case */
			err = g_error_new(m1b_gquark_log, 431, "No meta2 linked with this reference");
		}

		/* try to delete the reference, don't take care of the error */
		if (!err) {
			tmp = __destroy_container(sq3, cid, FALSE, &done);
			if (NULL != tmp)
				g_clear_error(&tmp);
		}
	}

	if (services)
		meta1_service_url_vclean(services);

	sqlx_repository_unlock_and_close_noerror(sq3);

	return err;
}

