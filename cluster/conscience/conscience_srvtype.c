#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "conscience.api"
#endif
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
	struct conscience_srvtype_s *srvtype;

	srvtype = g_try_malloc0(sizeof(struct conscience_srvtype_s));
	if (!srvtype) {
		ERROR("Memory allocation failure");
		abort();
		return NULL;
	}

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

static GByteArray *
conscience_srvtype_serialize_config(struct conscience_srvtype_s *srvtype,
    GError ** err)
{
	GByteArray *v, *encoded_kv;
	GSList *kv_list = NULL;
	GHashTable *ht = NULL;
	gchar wrkBuf[32];

	v = encoded_kv = NULL;
	ht = srvtype->config_ht;
	g_hash_table_ref(ht);

	/*Add the current timestamp */
	g_snprintf(wrkBuf, sizeof(wrkBuf), "%ld", time(0));
	v = g_byte_array_append(g_byte_array_new(),
	    (guint8 *) wrkBuf, strlen(wrkBuf) + 1);
	g_hash_table_insert(ht, "timestamp", v);

	/*convert the GHashTable to a list of KV */
	kv_list = key_value_pairs_convert_from_map(ht, FALSE, err);
	if (!kv_list) {
		GSETERROR(err, "Conversion HashTable->List failure");
		g_hash_table_unref(ht);
		return NULL;
	}

	/*encode the list */
	encoded_kv = key_value_pairs_marshall_gba(kv_list, err);
	if (!encoded_kv)
		GSETERROR(err, "Conversion List->ASN.1 failure");
	g_slist_foreach(kv_list, g_free1, NULL);
	g_slist_free(kv_list);

	g_hash_table_unref(ht);
	return encoded_kv;
}

GByteArray *
conscience_srvtype_get_config(struct conscience_srvtype_s * srvtype,
    GError ** err)
{
	if (!srvtype) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}

	if (!srvtype->config_serialized)
		srvtype->config_serialized = conscience_srvtype_serialize_config(srvtype, err);

	if (!srvtype->config_serialized) {
		GSETERROR(err,"Serialization failure");
		return NULL;
	}
	
	return g_byte_array_append(g_byte_array_new(), srvtype->config_serialized->data,
		srvtype->config_serialized->len);
}


struct conscience_srv_s *
conscience_srvtype_register_srv(struct conscience_srvtype_s *srvtype,
    GError ** err, const struct conscience_srvid_s *srvid)
{
	gsize desc_size;
	struct conscience_srv_s *service;

	if (!srvtype || !srvid) {
		GSETCODE(err, 500, "Invalid parameter");
		return NULL;
	}

	service = g_try_malloc0(sizeof(struct conscience_srv_s));
	if (!service) {
		GSETCODE(err, 500, "Memory allocation failure");
		return NULL;
	}

	memcpy(&(service->id), srvid, sizeof(struct conscience_srvid_s));
	service->tags = g_ptr_array_new();
	service->locked = FALSE;
	service->score.timestamp = time(0);
	service->score.value = -1;
	service->srvtype = srvtype;

	/*build the service description once for all*/
	desc_size = g_snprintf(service->description,sizeof(service->description),"%s/%s/",
		srvtype->conscience->ns_info.name, srvtype->type_name);
	addr_info_to_string(&(service->id.addr),
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


gint
conscience_srvtype_remove_expired(struct conscience_srvtype_s * srvtype,
    GError ** err, service_callback_f * callback, gpointer u)
{
	GHashTableIter iter;
	gpointer key, value;
	gint how_many;
	time_t oldest;

	if (!srvtype) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	how_many = 0U;
	oldest = time(0) - srvtype->score_expiration;

	g_hash_table_iter_init(&iter, srvtype->services_ht);
	while (g_hash_table_iter_next(&iter, &key, &value)) {

		struct conscience_srv_s *pService = value;

		if (!pService->locked && pService->score.timestamp < oldest) {
			if (callback)
				callback(pService, u);
			g_hash_table_iter_steal(&iter);
			conscience_srv_destroy(pService);
			how_many++;
		}
	}

	return how_many;
}

gboolean
conscience_srvtype_run_all(struct conscience_srvtype_s * srvtype,
    GError ** error, guint32 flags, service_callback_f * callback, gpointer udata)
{
	gboolean rc;
	time_t oldest;
	struct conscience_srv_s *beacon, *srv;

	if (!srvtype || !callback) {
		GSETERROR(error, "Invalid parameter");
		return FALSE;
	}

	rc = TRUE;
	if (flags & SRVTYPE_FLAG_INCLUDE_EXPIRED) {
		beacon = &(srvtype->services_ring);
		for (srv = beacon->next; rc && srv && srv != beacon; srv = srv->next)
			rc = callback(srv, udata);
	}
	else {
		oldest = time(0) - srvtype->score_expiration;
		beacon = &(srvtype->services_ring);
		for (srv = beacon->next; rc && srv && srv != beacon; srv = srv->next) {
			if (srv->locked || srv->score.timestamp > oldest)
				rc = callback(srv, udata);
		}
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

		time_t oldest;
		struct conscience_srv_s *beacon, *srv;

		oldest = time(0) - srvtype->score_expiration;
		beacon = &(srvtype->services_ring);

		for (srv = beacon->next; srv && srv != beacon;
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
		GSETCODE(err, 500, "Invalid parameter");
		return FALSE;
	}

	pE = NULL;
	if (expr_parse(expr_str, &pE)) {
		GSETCODE(err, 502, "Failed to parse the expression");
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

gboolean
conscience_srvtype_refresh(struct conscience_srvtype_s *srvtype,
    GError ** error, struct service_info_s *si, gboolean overwrite_score)
{
	struct conscience_srvid_s srvid;
	struct conscience_srv_s *p_srv;
	struct service_tag_s *tag_first = NULL;

	if (!srvtype || !si) {
		GSETERROR(error, "Invalid argument srvtype=%p srvinfo=%p",
		    (void *) srvtype, (void *) si);
		return FALSE;
	}
	memcpy(&(srvid.addr), &(si->addr), sizeof(addr_info_t));


	/* Get first launching tag if any and lock score to 0 if true */
	tag_first = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_FIRST);

	/*register the service if necessary */
	p_srv = conscience_srvtype_get_srv(srvtype, &srvid);
	if (!p_srv) {
		p_srv = conscience_srvtype_register_srv(srvtype, error, &srvid);
		if (!p_srv) {
			GSETERROR(error, "Service not found, registration impossible");
			return FALSE;
		}

		if (tag_first != NULL && tag_first->type == STVT_BOOL && tag_first->value.b) {
			DEBUG("Service [%s] lauched for the first time => locking score to 0", si->type);
			p_srv->score.value = 0;
			p_srv->locked = TRUE;
		}
		else
			p_srv->score.value = -1;
	}

	/* refresh the tags: create missing, replace existing
	 * (but the tags are not flushed before) */
	if (si->tags) {
		int i, max;
		struct service_tag_s *tag, *orig;

		TRACE("Refreshing tags for srv [%.*s]", (int)(LIMIT_LENGTH_SRVDESCR), p_srv->description);
		for (i = 0, max = si->tags->len; i < max; i++) {
			tag = g_ptr_array_index(si->tags, i);
			orig = conscience_srv_ensure_tag(p_srv, tag->name);
			service_tag_copy(orig, tag);
		}
	}

	/*now compute the score with the new tags */
	if (overwrite_score)
		memcpy(&(p_srv->score), &(si->score), sizeof(score_t));
	else if (!conscience_srv_compute_score(p_srv, error)) {
		GSETERROR(error, "Service data refreshed, but score computation failed!");
		return FALSE;
	}

	return TRUE;
}
