/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <sqliterepo/sqliterepo.h>

#include "./internals.h"
#include "./compound_types.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

#define M1U(P) ((struct meta1_service_url_s*)(P))

static void __notify_services_by_cid(struct meta1_backend_s *m1,
		struct sqlx_sqlite3_s *sq3, struct oio_url_s *url);

static GError *__get_container_all_services(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, const char *srvtype,
		struct meta1_service_url_s ***result);

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
		for (; *uv; ++uv) {
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
	if (uv)
		for (; *uv; uv++)
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
	for (p = split; *p; p++) {
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
		for (; *uv; ++uv) {
			struct meta1_service_url_s **p, **utmp;
			if (NULL != (utmp = expand_url(*uv))) {
				for (p=utmp; *p; ++p)
					g_ptr_array_add(tmp, *p);
				g_free(utmp);
			}
		}
	}

	g_ptr_array_add(tmp, NULL);
	return (struct meta1_service_url_s**)g_ptr_array_free(tmp, FALSE);
}

static struct meta1_service_url_s*
_ids_to_url(gchar **ids)
{
	struct meta1_service_url_s *m1u = g_malloc0 (sizeof(*m1u));
	meta1_urlv_shift_addr(ids);
	char *joined = g_strjoinv(",", ids);
	g_strlcpy (m1u->host, joined, sizeof(m1u->host));
	g_free(joined);
	return m1u;
}

//------------------------------------------------------------------------------

static GError *
__del_container_srvtype_properties(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, const char *srvtype)
{
	GError *err = NULL;
	gint rc;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db,
			"DELETE FROM properties WHERE cid = ? AND name LIKE ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		err = M1_SQLITE_GERROR(sq3->db, rc);
	} else {
		int len = strlen(srvtype)+10;
		gchar *tmp_name = g_malloc0(sizeof(gchar)*len);
		if (tmp_name) {
			g_snprintf(tmp_name, len, "%s.%%", srvtype);
			(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url),
					oio_url_get_id_size(url), NULL);
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
		struct oio_url_s *url, const char *srvtype)
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
		(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url),
				oio_url_get_id_size(url), NULL);
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
		struct oio_url_s *url, const char *srvtype, gint64 seq)
{
	static const char *sql = "DELETE FROM services WHERE cid = ? AND srvtype = ? AND seq = ?";
	sqlite3_stmt *stmt = NULL;
	GError *err = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
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
__del_container_services(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		const char *srvtype, gchar **urlv)
{
	gint64 seq;
	GError *err = NULL;
	guint line = 1;

	if (!urlv || !*urlv)
		err = __del_container_all_services(sq3, url, srvtype);
	else {
		for (; !err && *urlv; urlv++,line++) {
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
	}

	return err;
}

static GError *
__configure_service(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct meta1_service_url_s *m1url)
{
	static const char *sql = "UPDATE services SET args = ? "
		"WHERE cid = ? AND seq = ? AND srvtype = ?";
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_text(stmt, 1, m1url->args, -1, NULL);
		(void) sqlite3_bind_blob(stmt, 2, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
		(void) sqlite3_bind_int64(stmt, 3, m1url->seq);
		(void) sqlite3_bind_text(stmt, 4, m1url->srvtype, -1, NULL);
		sqlite3_step_debug_until_end (rc, stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
		if (!err && !sqlite3_changes(sq3->db))
			err = NEWERROR(CODE_SRV_NOLINK, "Service not found");
	}

	return err;
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
			"SELECT DISTINCT srvtype,url FROM services order by srvtype,url",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	// Run the result
	gpa = g_ptr_array_new();
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		struct meta1_service_url_s *u;
		u = g_malloc0(sizeof(struct meta1_service_url_s) +
				1 + sqlite3_column_bytes(stmt, 3));
		u->seq = 0;
		g_strlcpy(u->srvtype, (gchar*)sqlite3_column_text(stmt, 0),
				sizeof(u->srvtype));
		g_strlcpy(u->host,    (gchar*)sqlite3_column_text(stmt, 1),
				sizeof(u->host)-1);
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

#define PREFIX "SELECT seq,srvtype,url,args FROM services "

static GError *
__get_container_all_services(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		const char *srvtype, struct meta1_service_url_s ***result)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GPtrArray *gpa;
	int rc;

	/* Prepare the statement */
	if (oio_str_is_set(srvtype)) {
		sqlite3_prepare_debug(rc, sq3->db,
				PREFIX "WHERE cid = ? AND srvtype = ?", -1, &stmt, NULL);
		if (rc != SQLITE_OK)
			return M1_SQLITE_GERROR(sq3->db, rc);
		(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
		(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
	}
	else {
		sqlite3_prepare_debug(rc, sq3->db,
				PREFIX "WHERE cid = ?", -1, &stmt, NULL);
		if (rc != SQLITE_OK)
			return M1_SQLITE_GERROR(sq3->db, rc);
		(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
	}

	/* Run the result */
	gpa = g_ptr_array_new();
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		const gsize arglen = sqlite3_column_bytes(stmt, 3);
		struct meta1_service_url_s *u = g_malloc0(sizeof(struct meta1_service_url_s) + 1 + arglen);
		u->seq = sqlite3_column_int(stmt, 0);
		g_strlcpy(u->srvtype, (gchar*)sqlite3_column_text(stmt, 1), sizeof(u->srvtype));
		g_strlcpy(u->host, (gchar*)sqlite3_column_text(stmt, 2), sizeof(u->host)-1);
		memcpy(u->args, (gchar*)sqlite3_column_text(stmt, 3), arglen);
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
	meta1_url_sort(*result);
	return NULL;
}

static GError *
__save_service(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
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

	(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
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
__delete_service(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		const char *srvtype)
{
	gint rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db,
			"DELETE FROM services WHERE cid = ? AND srvtype = ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
	(void) sqlite3_bind_text(stmt, 2, srvtype, -1, NULL);
	sqlite3_step_debug_until_end (rc, stmt);
	if (rc != SQLITE_DONE && rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	return err;
}

//------------------------------------------------------------------------------

static gchar *
key_from_m1srvurl(struct meta1_backend_s *m1, struct meta1_service_url_s *url)
{
	return oio_make_service_key(m1->ns_name, url->srvtype, url->host);
}

// TODO(srvid): do not suppose url is an IP address
static oio_location_t *
__locations_from_m1srvurl(struct meta1_backend_s *m1,
		struct meta1_service_url_s **urls)
{
	GArray *out = g_array_new(TRUE, TRUE, sizeof(oio_location_t));
	struct meta1_service_url_s **cursor = NULL;
	for (cursor = urls; urls && *cursor; cursor++) {
		struct meta1_service_url_s **extracted;
		extracted = expand_url(*cursor);
		gchar *key = key_from_m1srvurl(m1, *extracted);
		/* Search the service in the default pool. We don't know if the
		 * service is actually discoverable by this pool, but we rely on
		 * the fact that the call will be forwarded to a lb_world,
		 * which knows all services. */
		struct oio_lb_item_s *item = oio_lb__get_item_from_pool(
				m1->lb, (*extracted)->srvtype, key);
		if (item) {
			oio_location_t loc = item->location;
			g_array_append_val(out, loc);
			g_free(item);
		}
		g_free(key);
		meta1_service_url_cleanv(extracted);
		extracted = NULL;
	}
	return (oio_location_t*)g_array_free(out, FALSE);
}

static struct meta1_service_url_s *
__poll_services(struct meta1_backend_s *m1, guint replicas,
		struct compound_type_s *ct, guint seq,
		struct meta1_service_url_s **used, GError **err)
{
	GRID_DEBUG("Polling %u [%s]", replicas, ct->fulltype);

	// ----------------------------------------------------------------------
	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);
	/* `used` is a list of known services that we must replace, thus avoid. */
	oio_location_t *avoid = __locations_from_m1srvurl(m1, used);
	oio_location_t *known = NULL;
	if (ct->req.k && !strcmp(ct->req.k, NAME_TAGNAME_USER_IS_SERVICE)) {
		struct meta1_service_url_s *inplace[2] = {
				meta1_unpack_url(ct->req.v), NULL};
		/* If ct->req.v is not parseable, known will contain NULL */
		known = __locations_from_m1srvurl(m1, inplace);
		meta1_service_url_clean(inplace[0]);
	}
	void _on_id(oio_location_t loc, const char *id)
	{
		(void)loc;
		g_ptr_array_add(ids, g_strdup(id));
	}
	*err = oio_lb__patch_with_pool(
			m1->lb, ct->baretype, avoid, known, _on_id, NULL);
	if (*err) {
		g_prefix_error(err, "found only %u services matching the criteria: ",
				ids->len);
	}

	struct meta1_service_url_s *m1u = NULL;
	if (!*err) {
		g_ptr_array_add(ids, NULL);
		m1u = _ids_to_url((char**)ids->pdata);
		g_strlcpy(m1u->srvtype, ct->type, sizeof(m1u->srvtype));
		m1u->seq = seq;
	}

	g_ptr_array_free(ids, TRUE);
	g_free(known);
	g_free(avoid);

	return m1u;
}

static gboolean
_is_service_up(struct meta1_backend_s *m1, struct meta1_service_url_s *url)
{
	struct compound_type_s ct = {0};
	GError *err = compound_type_parse(&ct, url->srvtype);
	if (err) {
		g_clear_error(&err);
		return FALSE;
	}

	/* TODO @todo Make the same without memory allocation from the heap */
	gchar *key = oio_make_service_key(m1->ns_name, ct.baretype, url->host);
	struct oio_lb_item_s *item = oio_lb__get_item_from_pool(m1->lb, ct.baretype, key);
	g_free(key);

	const gboolean is_up = item ? (item->weight > 0) : FALSE;
	g_free(item);
	compound_type_clean(&ct);
	return is_up;
}

static gboolean
_is_any_service_up(struct meta1_backend_s *m1, struct meta1_service_url_s **src)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(src != NULL && *src != NULL);

	gboolean one_is_up = FALSE;

	for (; src && *src && !one_is_up ; src++) {
		struct meta1_service_url_s **extracted;
		if (NULL != (extracted = expand_url(*src))) {
			struct meta1_service_url_s **pe;
			for (pe = extracted; extracted && *pe && !one_is_up; pe++)
				one_is_up |= _is_service_up(m1, *pe);
			meta1_service_url_cleanv(extracted);
		}
	}

	return one_is_up;
}

static GError *
__get_container_service2(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, struct compound_type_s *ct,
		struct meta1_backend_s *m1, const char *last, enum m1v2_getsrv_e mode,
		gchar ***result, gboolean *renewed)
{
	GError *err = NULL;
	struct meta1_service_url_s **used = NULL;

	struct service_update_policies_s *pol;
	if (!(pol = meta1_backend_get_svcupdate(m1)))
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Bad NS/Policy pair");

	enum service_update_policy_e policy = service_howto_update(pol, ct->baretype);
	guint replicas = service_howmany_replicas(pol, ct->baretype);
	replicas = (replicas > 0 ? replicas : 1);

	/* Patches the constraint on the service type (if not set in the request)
	 * by the constraint set in the NS-wide storage policy. */
	compound_type_update_arg(ct, pol, FALSE);

	/* This special "tag" is used for services types that are to be linked
	 * to containers belonging to other services (e.g. there is a container
	 * for each rawx in the special "_RDIR" account). It tells the load
	 * balancer to compare the location of linked service against the
	 * location of the container owner. The __poll_services() function
	 * expects a string parseable as a meta1_service_url_s in ct->req.v,
	 * so we must build one. */
	if (ct->req.k && !strcmp(ct->req.k, NAME_TAGNAME_USER_IS_SERVICE)) {
		gchar srvurl[64] = {0};
		g_snprintf(srvurl, sizeof(srvurl), "1|%s|%s|",
				ct->req.v, oio_url_get(url, OIOURL_USER));
		oio_str_replace(&(ct->req.v), srvurl);
	}

	err = __get_container_all_services(sq3, url, ct->type, &used);
	if (NULL != err) {
		g_prefix_error(&err, "Preliminary lookup error : ");
		return err;
	}
	if (used && !*used) {
		g_free(used);
		used = NULL;
	}

	if (used) {
		/* Check the client knows the services currently in place */
		if (oio_str_is_set(last)) {
			gchar *descr = meta1_url_manifest(used);
			if (0 != strcmp(last, descr))
				err = NEWERROR(CODE_SHARD_CHANGE,
						"Manifest mismatch db[%s] req[%s]",
						descr, last);
			g_free0(descr);
			if (err) {
				meta1_service_url_cleanv(used);
				return err;
			}
		}

		/* Now there are conditions where there is no chance we need to
		 * renew the service, so just answer them */
		if (mode == M1V2_GETSRV_REUSE &&
				(policy == SVCUPD_KEEP || _is_any_service_up(m1, used))) {
			*result = pack_urlv(used);
			meta1_service_url_cleanv(used);
			return NULL;
		}
	} else {
		/* No service currently in use, so we should not accept a request
		 * that mentions the client knowns any service */
		if (oio_str_is_set(last)) {
			meta1_service_url_cleanv(used);
			return NEWERROR(CODE_SHARD_CHANGE,
					"Manifest mismatch db[] req[%s]", last);
		}
	}

	/* No service available, poll a new one */
	gint seq = urlv_get_max_seq(used);
	seq = (seq<0 ? 1 : seq+1);

	struct meta1_service_url_s *m1_url = NULL;
	if (NULL != (m1_url = __poll_services(m1, replicas, ct, seq, used, &err))) {
		if (!err && mode != M1V2_GETSRV_DRYRUN) {
			if (policy == SVCUPD_REPLACE)
				err = __delete_service(sq3, url, ct->type);
			if (NULL == err)
				err = __save_service(sq3, url, m1_url, TRUE);
			if (!err && renewed)
				*renewed = TRUE;
		}

		if (!err && result) {
			struct meta1_service_url_s **unpacked = expand_url(m1_url);
			struct meta1_service_url_s **tmp =
				(struct meta1_service_url_s**) oio_ext_array_concat((void**) unpacked, (void**) used);
			*result = pack_urlv(tmp);
			g_free(tmp);
			meta1_service_url_cleanv(unpacked);
		}
		g_free(m1_url);
	}

	meta1_service_url_cleanv(used);
	return err;
}

static GError *
__get_container_service(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, const char *srvtype,
		struct meta1_backend_s *m1, const char *last, enum m1v2_getsrv_e mode,
		gchar ***result, gboolean *renewed)
{
	GError *err = NULL;
	struct compound_type_s ct;

	if (NULL != (err = compound_type_parse(&ct, srvtype)))
		return err;
	err = __get_container_service2(sq3, url, &ct, m1, last, mode, result, renewed);
	compound_type_clean(&ct);
	return err;
}

/* ------------------------------------------------------------------------- */

/** @private */
struct m1v2_relink_input_s {
	struct meta1_backend_s *m1;
	struct sqlx_sqlite3_s *sq3;
	struct oio_url_s *url;
	struct compound_type_s *ct;
	struct meta1_service_url_s **kept;
	struct meta1_service_url_s **replaced;
	gboolean dryrun;
};

static struct meta1_service_url_s **
__parse_and_expand (const char *packed)
{
	if (!packed)
		return NULL;
	struct meta1_service_url_s *m1u, **out = NULL;
	if (NULL != (m1u = meta1_unpack_url (packed))) {
		out = expand_url (m1u);
		g_free (m1u);
	}
	return out;
}

/** Suitable as a qsort()-like hook */
static gint
_sorter (struct meta1_service_url_s **p0, struct meta1_service_url_s **p1)
{
	const gint64 s0 = (*p0)->seq, s1 = (*p1)->seq;
	if (s0 == s1)
		return strcmp ((*p0)->host, (*p1)->host);
	const int one = s0 > s1;
	return one ? one : -(s0 < s1);
}

static gboolean
_idem (struct meta1_service_url_s *u0, struct meta1_service_url_s *u1)
{
	return u0->seq == u1->seq && !strcmp(u0->srvtype, u1->srvtype);
}

/* Check if `all` array contains exactly the same items as the union
 * of `kept` and `replaced` arrays (order does not matter). */
static gboolean
__match_urlv (struct meta1_service_url_s **all, struct meta1_service_url_s **kept,
		struct meta1_service_url_s **replaced)
{
	struct meta1_service_url_s *ref = kept && *kept ? *kept : *replaced;

	gboolean rc = FALSE;
	GPtrArray *gpa_inplace = g_ptr_array_new ();
	GPtrArray *gpa_told = g_ptr_array_new ();

	/* build two arrays of URL we can safely sort */
	for (; *all; ++all) {
		if ((*all)->seq == ref->seq)
			g_ptr_array_add (gpa_inplace, *all);
	}
	if (kept) while (*kept)
		g_ptr_array_add (gpa_told, *(kept++));
	if (replaced) while (*replaced)
		g_ptr_array_add (gpa_told, *(replaced++));

	/* sort them */
	if (gpa_told->len != gpa_inplace->len)
		goto out;
	g_ptr_array_sort (gpa_inplace, (GCompareFunc)_sorter);
	g_ptr_array_sort (gpa_told, (GCompareFunc)_sorter);

	/* identical sorted arrays have equal items at each position */
	for (guint i=0; i<gpa_told->len; ++i) {
		if (0 != strcmp(M1U(gpa_told->pdata[i])->host, M1U(gpa_inplace->pdata[i])->host))
			goto out;
	}
	rc = TRUE;
out:
	g_ptr_array_free (gpa_inplace, TRUE);
	g_ptr_array_free (gpa_told, TRUE);
	return rc;
}

static GError *
__relink_container_services(struct m1v2_relink_input_s *in, gchar ***out)
{
	GError *err = NULL;
	struct meta1_service_url_s *packed = NULL;

	struct meta1_service_url_s *ref = (in->kept && in->kept[0])
			? in->kept[0] : in->replaced[0];

	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);

	/* check the services provided are those in place */
	struct meta1_service_url_s **inplace = NULL;
	err = __get_container_all_services (in->sq3, in->url, ref->srvtype, &inplace);
	if (!err) {
		struct meta1_service_url_s **newset = expand_url (*inplace);
		if (!__match_urlv(newset, in->kept, in->replaced))
			err = NEWERROR(CODE_USER_INUSE, "services changed");
		meta1_service_url_cleanv (newset);
	}
	meta1_service_url_cleanv (inplace);
	inplace = NULL;

	/* it is time to poll */
	if (!err) {
		struct service_update_policies_s *pol = meta1_backend_get_svcupdate(in->m1);
		EXTRA_ASSERT (pol != NULL);

		guint max_svc = service_howmany_replicas(pol, in->ct->baretype);

		oio_location_t *known = NULL;
		oio_location_t *avoids = NULL;
		if (in->kept)
			known = __locations_from_m1srvurl(in->m1, in->kept);
		if (in->replaced)
			avoids = __locations_from_m1srvurl(in->m1, in->replaced);

		if (g_strv_length((char**)known) >= max_svc) {
			err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Too many services kept");
		} else {
			void _on_id(oio_location_t loc UNUSED, const char *id) {
				g_ptr_array_add(ids, g_strdup(id));
			}
			err = oio_lb__patch_with_pool(in->m1->lb, in->ct->baretype,
					avoids, known, _on_id, NULL);
			if (err) {
				g_prefix_error(&err,
						"found only %u services matching the criteria: ",
						ids->len);
			}
			g_ptr_array_add(ids, NULL);
		}

		g_free(avoids);
		g_free(known);
	}

	/* Services have been polled, them save them.
	 * We MUST use the same SEQ number. Since the service are packed in one
	 * entry, we can save them with a single SQL statement. */
	if (!err && !in->dryrun) {
		packed = _ids_to_url((char**)ids->pdata);
		packed->seq = ref->seq;
		strcpy (packed->srvtype, ref->srvtype);
		err = __save_service (in->sq3, in->url, packed, TRUE);
	}

	/* if the checks, polling and storage succeeded, prepare the output for
	 * the caller */
	if (!err) {
		struct meta1_service_url_s **newset = expand_url (packed);
		*out = pack_urlv (newset);
		meta1_service_url_cleanv (newset);
	}

	g_ptr_array_free(ids, TRUE);
	meta1_service_url_clean (packed);
	return err;
}

/* ------------------------------------------------------------------------- */

GError*
meta1_backend_services_config(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *packedurl)
{
	GError *err = __check_backend_events (m1);
	if (err) return err;

	struct meta1_service_url_s *m1url;
	if (!(m1url = meta1_unpack_url(packedurl)))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid URL");

	GRID_DEBUG("About to reconfigure [%s] [%"G_GINT64_FORMAT"] [%s] [%s]",
			m1url->srvtype, m1url->seq, m1url->host, m1url->args);

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) { g_free(m1url); return err; }

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, FALSE, NULL)))
			err = __configure_service(sq3, url, m1url);
		if (!(err = sqlx_transaction_end(repctx, err)))
			__notify_services_by_cid(m1, sq3, url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	g_free(m1url);
	return err;
}

GError*
meta1_backend_services_set(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *packedurl,
		gboolean autocreate, gboolean force)
{
	GError *err = __check_backend_events (m1);
	if (err) return err;

	struct meta1_service_url_s *m1url;
	if (!(m1url = meta1_unpack_url(packedurl)))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid URL");

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) { g_free(m1url); return err; }

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, autocreate, NULL)))
			err = __save_service(sq3, url, m1url, force);
		if (!(err = sqlx_transaction_end(repctx, err)))
			__notify_services_by_cid(m1, sq3, url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	g_free(m1url);

	/* XXX JFS: ugly quirk until we find a pretty way to distinguish the
	 * commit errors (e.g. it can fail because of a replication error or
	 * a constraint violation) */
	if (err && NULL != strstr(err->message, "UNIQUE"))
		err->code = CODE_SRV_ALREADY;

	return err;
}

GError *
meta1_backend_services_all(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar ***result)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		struct meta1_service_url_s **used = NULL;
		if (NULL != (err = __get_all_services(sq3, &used)))
			g_prefix_error(&err, "Query error: ");
		else {
			struct meta1_service_url_s **expanded = expand_urlv(used);
			*result = pack_urlv(expanded);
			meta1_service_url_cleanv(expanded);
			meta1_service_url_cleanv(used);
		}
		err = sqlx_transaction_end(repctx, err);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError *
meta1_backend_services_link (struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *srvtype,
		const char *last,
		gboolean autocreate,
		gchar ***result)
{
	EXTRA_ASSERT(result != NULL);

	GError *err = __check_backend_events (m1);
	if (err) return err;

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		gboolean renewed = FALSE;
		if (!(err = __info_user(sq3, url, autocreate, NULL))) {
			err = __get_container_service(sq3, url, srvtype, m1, last, M1V2_GETSRV_REUSE, result, &renewed);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		if (!(err = sqlx_transaction_end(repctx, err))) {
			if (renewed)
				__notify_services_by_cid(m1, sq3, url);
		}
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError*
meta1_backend_services_renew(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *srvtype,
		const char *last, gboolean autocreate,
		gchar ***result)
{
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	if (!oio_str_is_set(srvtype))
		return BADREQ("Missing service type");

	GError *err = __check_backend_events (m1);
	if (err) return err;

	gboolean renewed = FALSE;
	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, autocreate, NULL))) {
			err = __get_container_service(sq3, url,
					srvtype, m1, last, M1V2_GETSRV_RENEW, result, &renewed);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		if (!(err = sqlx_transaction_end(repctx, err)) && renewed) {
			if (renewed)
				__notify_services_by_cid(m1, sq3, url);
		}
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError *
meta1_backend_services_list(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *srvtype, gchar ***result,
		gint64 deadline)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);

	gboolean retry = TRUE;
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;

label_retry:
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (err) {
		if (retry && err->code == CODE_RANGE_NOTFOUND) {
			retry = FALSE;
			// Try to reload the prefixes
			gboolean meta0_ok = FALSE;
			GArray *updated_prefixes = NULL;
			GError *err_load = meta1_prefixes_load(m1->prefixes,
					oio_url_get(url, OIOURL_NS),
					sqlx_repository_get_local_addr(m1->repo),
					&updated_prefixes, &meta0_ok, m1->nb_digits, deadline);
			if (err_load || !meta0_ok) {
				if (err_load) g_error_free(err_load);
				return err;
			}
			g_error_free(err);
			if (updated_prefixes)
				g_array_free(updated_prefixes, TRUE);
			goto label_retry;
		}
		return err;
	}

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
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
		err = sqlx_transaction_end(repctx, err);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError*
meta1_backend_services_unlink(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *srvtype, gchar **urlv)
{
	GError *err = __check_backend_events (m1);
	if (err) return err;

	EXTRA_ASSERT(srvtype != NULL);
	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			err = __del_container_services(sq3, url, srvtype, urlv);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		if (!(err = sqlx_transaction_end(repctx, err)))
			__notify_services_by_cid(m1, sq3, url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError*
meta1_backend_services_relink(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *kept, const char *replaced,
		gboolean dryrun, gchar ***out)
{
	EXTRA_ASSERT(out != NULL);

	GError *err = __check_backend_events (m1);
	if (err) return err;

	struct meta1_service_url_s **ukept = NULL, **urepl = NULL;
	/* fields to be prefetched */
	struct compound_type_s ct = {0};

	ukept = __parse_and_expand (kept);
	urepl = __parse_and_expand (replaced);

	/* prefetch the compound type (so it is parsed only once) */
	if (!oio_url_has(url, OIOURL_TYPE)) {
		err = BADREQ("Invalid OIOURL: missing service type");
		goto out;
	}
	/* Sanity check: we must receive at least one service */
	if ((!ukept || !*ukept) && (!urepl || !*urepl)) {
		err = NEWERROR (CODE_BAD_REQUEST, "Missing URL set");
		goto out;
	}

	struct meta1_service_url_s *ref = ukept && *ukept ? *ukept : *urepl;
	if (NULL != (err = compound_type_parse(&ct, ref->srvtype)))
		goto out;

	/* Sanity check: all the services must have the same <seq,type> */
	for (struct meta1_service_url_s **p = ukept; ukept && *p; ++p) {
		if (!_idem(*p, ref)) {
			err = BADREQ("Mismatch in URL set (%s)", "kept");
			goto out;
		}
	}
	for (struct meta1_service_url_s **p = urepl; urepl && *p; ++p) {
		if (!_idem(*p, ref)) {
			err = BADREQ("Mismatch in URL set (%s)", "replaced");
			goto out;
		}
	}
	/* Sanity check: all the kept/replaced services must have the type of
	 * the oio_url */
	for (struct meta1_service_url_s **p = urepl; urepl && *p; ++p) {
		if (0 != strcmp((*p)->srvtype, ct.fulltype)) {
			err = BADREQ("Service type mismatch (URL vs. kept/replaced)");
			goto out;
		}
	}

	/* Call the backend logic now */
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3))) {
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			if (!(err = __info_user(sq3, url, FALSE, NULL))) {
				struct m1v2_relink_input_s in = {
					.m1 = m1, .sq3 = sq3, .url = url,
					.ct = &ct, .kept = ukept, .replaced = urepl,
					.dryrun = dryrun
				};
				err = __relink_container_services(&in, out);
			}
			if (!(err = sqlx_transaction_end(repctx, err))) {
				if (!dryrun)
					__notify_services_by_cid(m1, sq3, url);
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

out:
	meta1_service_url_cleanv (ukept);
	meta1_service_url_cleanv (urepl);
	compound_type_clean (&ct);
	return err;
}

/* ------------------------------------------------------------------------- */

static GError *
__notify_services(struct meta1_backend_s *m1, struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url)
{
	if (!m1->notifier)
		return NULL;

	struct meta1_service_url_s **services = NULL;
	GError *err = __get_container_all_services(sq3, url, NULL, &services);
	if (!err) {
		struct meta1_service_url_s **services2 = expand_urlv(services);
		GString *notif = oio_event__create ("account.services", url);
		g_string_append_static (notif, ",\"data\":[");
		if (services2) {
			for (struct meta1_service_url_s **svc = services2; *svc ; svc++) {
				if (svc != services2) // not at the beginning
					g_string_append_c(notif, ',');
				meta1_service_url_encode_json(notif, *svc);
			}
		}
		g_string_append_static(notif, "]}");

		oio_events_queue__send (m1->notifier, g_string_free(notif, FALSE));

		meta1_service_url_cleanv(services2);
		meta1_service_url_cleanv(services);
	}
	return err;
}

static void
__notify_services_by_cid(struct meta1_backend_s *m1, struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url)
{
	struct oio_url_s **urls = NULL;
	sqlx_exec (sq3->db, "BEGIN");
	GError *err = __info_user(sq3, url, FALSE, &urls);
	if (!err) {
		oio_url_set (urls[0], OIOURL_NS, m1->ns_name);
		err = __notify_services(m1, sq3, url);
	}
	sqlx_exec (sq3->db, "ROLLBACK");
	oio_url_cleanv (urls);

	if (err) {
		GRID_WARN("Failed to notify the services for [%s]: %s",
				oio_url_get(url, OIOURL_HEXID), err->message);
		g_clear_error(&err);
	}
}

GError *
meta1_backend_notify_services(struct meta1_backend_s *m1, struct oio_url_s *url)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		__notify_services_by_cid(m1, sq3, url);
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
	return err;
}

