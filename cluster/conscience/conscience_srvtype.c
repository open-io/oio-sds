/*
OpenIO SDS cluster
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

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./conscience_srvtype.h"
#include "./conscience_srv.h"
#include "./conscience.h"

static guint
hash_service_id(gconstpointer p)
{
	return djb_hash_buf(p, sizeof(struct conscience_srvid_s));
}

static gboolean
equal_service_id(gconstpointer p1, gconstpointer p2)
{
	if (!p1 || !p2)
		return FALSE;
	return (0 == memcmp(p1, p2, sizeof(struct conscience_srvid_s)));
}

static void
destroy_gba(gpointer p)
{
	if (p)
		g_byte_array_free((GByteArray *) p, TRUE);
}

struct conscience_srvtype_s *
conscience_srvtype_create(struct conscience_s *conscience, const char *type)
{
	struct conscience_srvtype_s *srvtype = g_malloc0(sizeof(struct conscience_srvtype_s));

	/*sets a default expression that always fits*/
	if (!conscience_srvtype_set_type_expression(srvtype, NULL, "100")) {
		ERROR("Failed to force the score to 100");
		conscience_srvtype_destroy(srvtype);
		return NULL;
	}

	/*allocate the hashtables */
	srvtype->services_ht = g_hash_table_new_full(hash_service_id,
			equal_service_id, NULL, NULL);
	srvtype->config_ht = g_hash_table_new_full(g_str_hash,
			g_str_equal, g_free, destroy_gba);
	if (!srvtype->config_ht || !srvtype->services_ht) {
		ERROR("HT allocation failure");
		conscience_srvtype_destroy(srvtype);
		abort();
		return NULL;
	}

	if (type)
		g_strlcpy(srvtype->type_name, type, sizeof(srvtype->type_name));
	srvtype->alert_frequency_limit = 0;
	srvtype->score_variation_bound = 0;
	srvtype->conscience = conscience;
	srvtype->services_ring.next = srvtype->services_ring.prev = &(srvtype->services_ring);
	return srvtype;
}

void
conscience_srvtype_destroy(struct conscience_srvtype_s *srvtype)
{
	if (!srvtype)
		return;

	conscience_srvtype_flush(srvtype);

	if (srvtype->config_serialized)
		g_byte_array_free(srvtype->config_serialized, TRUE);
	if (srvtype->config_ht)
		g_hash_table_destroy(srvtype->config_ht);
	if (srvtype->services_ht)
		g_hash_table_destroy(srvtype->services_ht);
	if (srvtype->score_expr)
		expr_clean(srvtype->score_expr);
	if (srvtype->score_expr_str) {
		*(srvtype->score_expr_str) = '\0';
		g_free(srvtype->score_expr_str);
	}

	memset(srvtype, 0x00, sizeof(struct conscience_srvtype_s));
	g_free(srvtype);
}

struct conscience_srv_s *
conscience_srvtype_get_srv(struct conscience_srvtype_s *srvtype,
    const struct conscience_srvid_s *srvid)
{
	if (!srvtype || !srvid)
		return NULL;
	return g_hash_table_lookup(srvtype->services_ht, srvid);
}

void
conscience_srvtype_remove_srv(struct conscience_srvtype_s *srvtype,
    struct conscience_srvid_s *srvid)
{
	struct conscience_srv_s *srv;

	if (!srvtype || !srvid)
		return;
	srv = g_hash_table_lookup(srvtype->services_ht, srvid);
	if (srv) {
		/*remove from the hash */
		g_hash_table_remove(srvtype->services_ht, srvid);
		/*remove from the ring */
		srv->prev->next = srv->next;
		srv->next->prev = srv->prev;
		srv->next = srv->prev = NULL;
		/*wipe out */
		conscience_srv_destroy(srv);
	}
}

struct conscience_srv_s *
conscience_srvtype_register_srv(struct conscience_srvtype_s *srvtype,
    GError ** err, const struct conscience_srvid_s *srvid)
{
	gsize desc_size;
	struct conscience_srv_s *service;

	if (!srvtype || !srvid) {
		GSETCODE(err, CODE_INTERNAL_ERROR, "Invalid parameter");
		return NULL;
	}

	service = g_malloc0(sizeof(struct conscience_srv_s));
	memcpy(&(service->id), srvid, sizeof(struct conscience_srvid_s));
	service->tags = g_ptr_array_new();
	service->locked = FALSE;
	service->score.timestamp = oio_ext_monotonic_seconds ();
	service->score.value = -1;
	service->srvtype = srvtype;

	/*build the service description once for all*/
	desc_size = g_snprintf(service->description,sizeof(service->description),"%s/%s/",
		srvtype->conscience->ns_info.name, srvtype->type_name);
	grid_addrinfo_to_string(&(service->id.addr),
		service->description+desc_size,sizeof(service->description)-desc_size);

	/*register the service with its ID*/
	g_hash_table_insert(srvtype->services_ht, &(service->id), service);

	/*ring insertion */
	srvtype->services_ring.next->prev = service;
	service->prev = &(srvtype->services_ring);

	service->next = srvtype->services_ring.next;
	srvtype->services_ring.next = service;

	return service;
}

guint
conscience_srvtype_remove_expired(struct conscience_srvtype_s * srvtype,
    service_callback_f * callback, gpointer u)
{
	g_assert_nonnull (srvtype);

	guint count = 0U;

	time_t oldest = oio_ext_monotonic_seconds();
	if (oldest > srvtype->score_expiration)
		oldest -= srvtype->score_expiration;
	else
		oldest = 0;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, srvtype->services_ht);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct conscience_srv_s *pService = value;
		if (!pService->locked && pService->score.timestamp < oldest) {
			if (pService->score.value > 0) {
				if (callback)
					callback(pService, u);
				pService->score.value = 0;
			}
			count++;
		}
	}

	return count;
}

gboolean
conscience_srvtype_run_all(struct conscience_srvtype_s * srvtype,
    GError ** error, guint32 flags, service_callback_f * callback, gpointer udata)
{
	if (!srvtype || !callback) {
		GSETERROR(error, "Invalid parameter");
		return FALSE;
	}

	gboolean rc = TRUE;
	time_t oldest = oio_ext_monotonic_seconds () - srvtype->score_expiration;

	const struct conscience_srv_s *beacon = &(srvtype->services_ring);
	for (struct conscience_srv_s *srv = beacon->next;
			rc && srv != NULL && srv != beacon;
			srv = srv->next) {
		if (srv->locked || srv->score.timestamp > oldest)
			rc = callback(srv, udata);
	}

	if (rc && (flags & SRVTYPE_FLAG_ADDITIONAL_CALL))
		rc = callback(NULL, udata);

	return rc;
}

guint
conscience_srvtype_count_srv(struct conscience_srvtype_s * srvtype,
    gboolean include_expired)
{
	guint count = 0U;

	if (!srvtype)
		return 0U;

	if (include_expired)
		return g_hash_table_size(srvtype->services_ht);
	else {
		time_t oldest = oio_ext_monotonic_seconds () - srvtype->score_expiration;
		struct conscience_srv_s *beacon = &(srvtype->services_ring);

		for (struct conscience_srv_s *srv = beacon->next;
				srv && srv != beacon;
				srv = srv->next) {
			if (srv->score.timestamp < oldest)
				break;
			count++;
		}
	}

	return count;
}

void
conscience_srvtype_init(struct conscience_srvtype_s *srvtype)
{
	if (!srvtype) {
		WARN("Invalid parameter");
		return;
	}

	conscience_srvtype_set_type_expression(srvtype, NULL, "100");
	srvtype->alert_frequency_limit = 30;
	srvtype->score_expiration = 300;
	srvtype->score_variation_bound = 5;
}

gboolean
conscience_srvtype_set_type_expression(struct conscience_srvtype_s * srvtype,
	GError ** err, const gchar * expr_str)
{
	struct expr_s *pE;

	if (!srvtype || !expr_str) {
		GSETCODE(err, ERRCODE_PARAM, "Invalid parameter");
		return FALSE;
	}

	pE = NULL;
	if (expr_parse(expr_str, &pE)) {
		GSETCODE(err, CODE_INTERNAL_ERROR, "Failed to parse the expression");
		return FALSE;
	}

	/*replaces the string */
	if (srvtype->score_expr_str)
		g_free(srvtype->score_expr_str);
	if (srvtype->score_expr)
		expr_clean(srvtype->score_expr);

	srvtype->score_expr_str = g_strdup(expr_str);
	srvtype->score_expr = pE;
	return TRUE;
}

void
conscience_srvtype_flush(struct conscience_srvtype_s *srvtype)
{
	guint counter;
	struct conscience_srv_s *beacon, *cur, *nxt;

	if (!srvtype)
		return;

	g_hash_table_steal_all(srvtype->services_ht);

	counter = 0;
	beacon = &(srvtype->services_ring);
	for (cur = beacon->next; cur && cur != beacon; cur = nxt) {
		nxt = cur->next;
		conscience_srv_destroy(cur);
		counter++;
	}

	DEBUG("Service type [%s] flushed, [%u] services removed",
	    srvtype->type_name, counter);
}

struct conscience_srv_s *
conscience_srvtype_refresh(struct conscience_srvtype_s *srvtype, struct service_info_s *si)
{
	g_assert_nonnull (srvtype);
	g_assert_nonnull (si);

	struct conscience_srvid_s srvid;
	memcpy(&(srvid.addr), &(si->addr), sizeof(addr_info_t));

	struct service_tag_s *tag_first = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_FIRST);
	gboolean first = tag_first && tag_first->type == STVT_BOOL && tag_first->value.b;

	/*register the service if necessary */
	struct conscience_srv_s *p_srv = conscience_srvtype_get_srv(srvtype, &srvid);
	if (!p_srv) {
		p_srv = conscience_srvtype_register_srv(srvtype, NULL, &srvid);
		g_assert_nonnull (p_srv);
		p_srv->score.value = -1;
		p_srv->score.timestamp = 0;
	}

	/* refresh the tags: create missing, replace existing
	 * (but the tags are not flushed before) */
	if (si->tags) {
		TRACE("Refreshing tags for srv [%.*s]",
				(int)(LIMIT_LENGTH_SRVDESCR), p_srv->description);
		const guint max = si->tags->len;
		for (guint i = 0; i < max; i++) {
			struct service_tag_s *tag = g_ptr_array_index(si->tags, i);
			if (tag == tag_first) continue;
			struct service_tag_s *orig = conscience_srv_ensure_tag(p_srv, tag->name);
			service_tag_copy(orig, tag);
		}
	}

	p_srv->score.timestamp = oio_ext_monotonic_seconds ();
	if (si->score.value == SCORE_UNSET || si->score.value == SCORE_UNLOCK) {
		if (first) {
			GRID_TRACE2("SRV first [%s]", p_srv->description);
			p_srv->score.value = 0;
			p_srv->locked = TRUE;
		} else {
			if (si->score.value == SCORE_UNLOCK) {
				if (p_srv->locked) {
					GRID_TRACE2("SRV unlocked [%s]", p_srv->description);
					p_srv->locked = FALSE;
					p_srv->score.value = CLAMP (p_srv->score.value, SCORE_DOWN, SCORE_MAX);
				} else {
					GRID_TRACE2("SRV already unlocked [%s]", p_srv->description);
				}
			} else { /* UNSET, a.k.a. regular computation */
				if (p_srv->locked) {
					GRID_TRACE2("SRV untouched [%s]", p_srv->description);
				} else {
					GError *err = NULL;
					if (!conscience_srv_compute_score(p_srv, &err)) {
						GRID_TRACE2("SRV error [%s]: (%d) %s", p_srv->description, err->code, err->message);
						g_clear_error (&err);
					} else {
						GRID_TRACE2("SRV refreshed [%s]", p_srv->description);
					}
				}
			}
		}
	} else { /* LOCK */
		p_srv->score.value = CLAMP(si->score.value, SCORE_DOWN, SCORE_MAX);
		if (p_srv->locked) {
			GRID_TRACE2("SRV already locked [%s]", p_srv->description);
		} else {
			p_srv->locked = TRUE;
			GRID_TRACE2("SRV locked [%s]", p_srv->description);
		}
	}

	return p_srv;
}
