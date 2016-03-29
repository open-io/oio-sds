/*
OpenIO SDS meta0v2
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

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "./meta0_backend.h"
#include "./meta0_utils.h"
#include "./internals.h"
#include "./meta0_prefixassign.h"

struct meta1_assignment_s
{
	gchar *addr;
	guint score;  // Number of prefixes managed
	gboolean available;
	gboolean used;
	GArray *prefixes;  // Array of assigned prefixes
};

struct meta0_assign_context_s
{
	GDateTime *last_assign_time;
	GPtrArray *m1_by_prefix_array;
	GHashTable *m1_assign_by_addr;

	GHashTable *working_m1_assign_by_addr;

	guint8 *treat_prefixes;
	guint replica, avgscore;
};

static struct meta0_assign_context_s *context=NULL;

static guint period_between_two_assign = 10;  // in minute
static guint trigger_assignment = 5;  // percent

/* ----------------------------------------------------------------------------------------*/

static void
_free_meta0_assign_meta1(struct meta1_assignment_s *aM1)
{
	if (!aM1)
		return;
	if (aM1->prefixes)
		g_array_free(aM1->prefixes, TRUE);
	if (aM1->addr)
		g_free(aM1->addr);
}

static void
_gfree_map_meta0_assign_meta1(gpointer p1)
{
	if (p1) {
		_free_meta0_assign_meta1((struct meta1_assignment_s *) p1);
	}
}

/* ----------------------------------------------------------------------------------------*/

static struct meta1_assignment_s*
_unpack_meta1ref(gchar *s_meta1ref)
{
	EXTRA_ASSERT(s_meta1ref != NULL);

	struct meta1_assignment_s *assignment;

	assignment = g_malloc0(sizeof(struct meta1_assignment_s));
	gchar **split_result = g_strsplit(s_meta1ref, "|", -1);

	if (g_strv_length(split_result) != 3)
		return NULL;

	assignment->addr = g_strdup(split_result[0]);
	assignment->used = g_ascii_strtoll(split_result[1], NULL, 10) == 0;
	assignment->score = g_ascii_strtoll(split_result[2], NULL, 10);
	g_strfreev(split_result);

	return assignment;
}

static gchar *
_pack_meta1ref(struct meta1_assignment_s *m1ref)
{
	gchar nb[16] = {0};
	g_snprintf(nb, sizeof(nb), "%d", m1ref->score);
	gchar *result = meta0_utils_pack_meta1ref(
			m1ref->addr, m1ref->used? "1" : "0", nb);
	return result;
}

static GHashTable*
_meta1ref_array_to_map(GPtrArray *array)
{
	GHashTable *result;
	guint i, max;

	result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (i = 0, max = array->len; i < max; i++) {
		struct meta1_assignment_s *m1 = _unpack_meta1ref(array->pdata[i]);
		if (m1)
			g_hash_table_insert(result, m1->addr, m1);
	}

	return result;
}

static GPtrArray*
_meta1ref_map_to_array(GHashTable *map)
{
	GPtrArray *result;
	GHashTableIter iter;
	gpointer key, value;

	result = g_ptr_array_new();

	g_hash_table_iter_init(&iter, map);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct meta1_assignment_s *mRef = value;

		g_ptr_array_add(result, _pack_meta1ref(mRef));
	}
	return result;
}

/* ----------------------------------------------------------------------------------------*/

static void
_treat_prefix(guint8 *cache, const guint8 *prefix)
{
	guint16 slot = meta0_utils_bytes_to_prefix(prefix);
	cache[slot / 8] |= (0x01 << (slot % 8));
}

static gboolean
_is_treat_prefix(guint8 *cache, const guint8 *prefix)
{
	guint16 slot = meta0_utils_bytes_to_prefix(prefix);
	return cache[slot / 8] & (0x01 << (slot % 8));
}

static gint
meta0_assign_sort_by_score(gconstpointer a, gconstpointer b)
{
	const struct meta1_assignment_s *si_a, *si_b;

	if (!a && b)
		return 1;
	if (a && !b)
		return -1;
	if (a == b)
		return 0;
	si_a = a;
	si_b = b;
	return si_b->score - si_a->score;
}

/* ----------------------------------------------------------------------------------------*/

static gboolean
_select_prefix(GArray *prefixes, guint8 *treat_prefixes)
{
	if (!prefixes) {
		return FALSE;
	}

	if (prefixes->len != 0) {
		guint8 *prefix = (guint8 *)prefixes->data;
		if(!_is_treat_prefix(treat_prefixes, prefix)) {
			GRID_TRACE("select prefix %02X%02X ", prefix[0], prefix[1]);
			return TRUE;
		}

		prefixes = g_array_remove_index(prefixes, 0);

		if (prefixes->len != 0) {
			return _select_prefix(prefixes, treat_prefixes);
		}
	}

	g_array_free(prefixes, TRUE);
	prefixes = NULL;

	return FALSE;
}

static struct meta1_assignment_s*
_select_source_assign_m1(GList *lst, guint8 *treat_prefixes, const guint avgscore)
{
	if (lst == NULL)
		return NULL;
	struct meta1_assignment_s *aM1 = (g_list_first(lst))->data;

	if (aM1->score <= avgscore)
		return NULL;

	// check current prefix
	GArray *prefixes = aM1->prefixes;
	if (prefixes) {
		if (!_select_prefix(prefixes, treat_prefixes)) {
			aM1->available = FALSE;
			aM1->prefixes = NULL;
		}
	} else {
		aM1->available = FALSE;
	}

	if (!aM1->available) {
		lst = g_list_delete_link(lst, lst);
		return _select_source_assign_m1(lst, treat_prefixes, avgscore);
	}

	GRID_TRACE("select source meta1 %s, score %d", aM1->addr, aM1->score);
	return aM1;
}

static gchar *
_host(const char *s0)
{
	if (!s0)
		return NULL;
	gchar *s = strrchr(s0, ':');
	if (!s)
		return NULL;
	return g_strndup (s0, s-s0);
}

static struct meta1_assignment_s*
_select_dest_assign_m1(GList *lst, const struct meta1_assignment_s *m1_old,
		guint8 *prefix_in, gboolean unref, gboolean force)
{
	guint8 *prefix;
	if (m1_old)
		prefix = (guint8 *)(m1_old->prefixes)->data;
	else {
		if (prefix_in)
			prefix = prefix_in;
		else
			return NULL;
	}

	/* Select the meta1 with the lowest score */
	lst = g_list_last(lst);
	struct meta1_assignment_s *m1_new = lst->data;

	gboolean loop = TRUE;
	gchar *shost = NULL, *dhost = NULL, *host = NULL;

	guint avgscore = context->avgscore;
	gchar **urls = meta0_utils_array_get_urlv(
			context->m1_by_prefix_array, prefix);

	if (!urls) {
		/* The current prefix is assigned to no meta1.
		 * Assign it to m1_new (the lowest scored meta1). */
		goto cleanup;
	}
	gsize urls_len = g_strv_length(urls);

	if (m1_old)
		shost = _host(m1_old->addr);

	for (; loop && lst; lst = g_list_previous(lst)) {
		m1_new = lst->data;
		if (m1_new == NULL || (m1_new->score >= avgscore && !unref)) {
			/* We reached the end of the list or a score higher than the
			 * average (which is a problem when rebalancing). */
			loop = FALSE;
			m1_new = NULL;
		} else {
			dhost = _host(m1_new->addr);
			for (gsize i = 0; i < urls_len; i++) {
				if (m1_old && !g_strcmp0(urls[i], m1_old->addr)) {
					/* We found the old meta1 */
					continue;
				} else if (!g_strcmp0(urls[i], m1_new->addr)) {
					/* The currently selected meta1 already manages
					 * the prefix, we must find another one. */
					loop = TRUE;
					break;
				} else if ((host = _host(urls[i])) != NULL) {
					if (!g_strcmp0(host, dhost) &&
							(shost == NULL || g_strcmp0(host, shost))) {
						if (!force) {
							/* The currently selected meta1 is on the same
							 * host as another one managing the prefix.
							 * Unless we don't care about the distance, we
							 * must find another one. */
							loop = TRUE;
							oio_str_clean(&host);
							break;
						}
					}
					loop = FALSE;
					oio_str_clean(&host);
				}
			}
		}
		oio_str_clean(&dhost);
		oio_str_clean(&host);
	}

cleanup:
	g_strfreev(urls);
	oio_str_clean(&shost);

	if (!m1_new) {
		GRID_TRACE("NO meta1 dest found");
	}
	return m1_new;
}

static void
_remove_first_prefix_to_assign_meta1(struct meta1_assignment_s *m1)
{

	GArray *prefixes = m1->prefixes;
	if (prefixes->len > 0)
		prefixes = g_array_remove_index(prefixes, 0);

	if (prefixes->len == 0) {
		m1->available = FALSE;
		m1->prefixes = NULL;
	}
}

static guint8*
_get_first_prefix_to_assign_meta1(struct meta1_assignment_s *m1)
{
	GArray *prefixes = m1->prefixes;
	if (prefixes) {
		if (prefixes->len > 0)
			return (guint8 *)&g_array_index(prefixes, guint8, 0);
	}
	return NULL;
}

static void
_increase_score(struct meta1_assignment_s *aM1)
{
	aM1->score++;
}

static void
_decrease_score(struct meta1_assignment_s *aM1)
{
	aM1->score--;
	if (aM1->score <= context->avgscore)
		aM1->available = FALSE;
}

static void
_replace(struct meta1_assignment_s *m1_old, struct meta1_assignment_s *m1_new)
{
	guint8 *prefix = (guint8 *)(m1_old->prefixes)->data;
	if (meta0_utils_array_replace(context->m1_by_prefix_array,
			prefix, m1_old->addr, m1_new->addr)) {
		_treat_prefix(context->treat_prefixes, prefix);
		_remove_first_prefix_to_assign_meta1(m1_old);
		_decrease_score(m1_old);
		_increase_score(m1_new);
	}
}

static GPtrArray*
_updated_meta1ref()
{
	return _meta1ref_map_to_array(context->working_m1_assign_by_addr);
}

static GError*
_assign(GList *working_m1list, GSList *unref_m1list)
{
	GError *error = NULL;
	guint nb_treat_prefixes = 0;
	struct meta1_assignment_s *m1_old, *m1_new;
	//unref meta1
	if (unref_m1list) {
		for (; unref_m1list; unref_m1list = unref_m1list->next) {
			m1_old = unref_m1list->data;
			guint8 *prefix = _get_first_prefix_to_assign_meta1(m1_old);
			while (m1_old->prefixes) {
				if (_is_treat_prefix(context->treat_prefixes, prefix)) {
					GRID_ERROR("prefix [%02X%02X] already treat", prefix[0], prefix[1]);
					error = NEWERROR(0, "Failed to remove Meta1 service");
				}
				m1_new = _select_dest_assign_m1(working_m1list, m1_old, NULL, TRUE, FALSE);
				if (!m1_new) {
					m1_new = _select_dest_assign_m1(working_m1list, m1_old, NULL, TRUE, TRUE);
					if (!m1_new) {
						error = NEWERROR(0,
								"Failed to assign prefix from meta1 %s: "
								"Not enough META1 to meet the requirements",
								m1_old->addr);
						return error;
					}
				}
				_replace(m1_old, m1_new);
				nb_treat_prefixes++;
			}
		}
	}

	gboolean loop = TRUE;

	do {
		m1_old = NULL;
		m1_new = NULL;
		// sort meta1 list
		working_m1list = g_list_sort(working_m1list, meta0_assign_sort_by_score);

		// election high meta1 and prefix
		m1_old = _select_source_assign_m1(working_m1list,
				context->treat_prefixes, context->avgscore);

		if (m1_old) {
			m1_new = _select_dest_assign_m1(working_m1list, m1_old, NULL, FALSE, FALSE);

			if (m1_new) {
				_replace(m1_old, m1_new);
				nb_treat_prefixes++;
			} else {
				_remove_first_prefix_to_assign_meta1(m1_old);
			}
		} else {
			loop = FALSE;
		}

		if (nb_treat_prefixes == CID_PREFIX_COUNT)
			loop = FALSE;

	} while (loop);

	GRID_TRACE("END %d prefix assigned", nb_treat_prefixes);
	return NULL;
}

/* ----------------------------------------------------------------------------------------*/

static GError *
_init_assign(gchar *ns_name, GList **working_m1list,GSList **unref_m1list)
{
	GSList *m1_list = NULL;
	GError *error = conscience_get_services (ns_name, NAME_SRVTYPE_META1, FALSE, &m1_list);
	if (!m1_list) {
		if (error) {
			GRID_ERROR("failed to init meta1 service list: (%d) %s",
					error->code, error->message);
			goto errorLabel;
		}
	}
	GRID_INFO("nb m1 cs %d", g_slist_length(m1_list));
	if (context->replica > g_slist_length(m1_list)) {
		GRID_ERROR("Number of meta1 services [%d] less than number of replication [%d]",
				g_slist_length(m1_list), context->replica);
		error = NEWERROR(EINVAL,
				"Number of meta1 services [%d] less than number of replication [%d]",
				g_slist_length(m1_list), context->replica);
		goto errorLabel;
	}
	if (context->replica <= 0) {
		GRID_ERROR("Invalid replica number [%d]", context->replica);
		error = NEWERROR(EINVAL, "Invalid replica number [%d]", context->replica);
		goto errorLabel;
	}

	// Duplicate the current prefix distribution and build a List
	GSList *prefixByMeta1 = meta0_utils_array_to_list(context->m1_by_prefix_array);

	GSList *l = NULL;
	for (; m1_list; m1_list = m1_list->next) {
		struct meta1_assignment_s *aM1;
		struct service_info_s *sInfo;
		gchar url[128] = {0};

		aM1 = g_malloc0(sizeof(struct meta1_assignment_s));

		sInfo = m1_list->data;

		grid_addrinfo_to_string(&(sInfo->addr), url, sizeof(url));
		aM1->addr = g_strdup(url);
		aM1->score = 0;
		aM1->available = FALSE;
		aM1->used = TRUE;

		l = prefixByMeta1;
		for (; l; l = l->next) {
			struct meta0_info_s *m0info;
			if (!(m0info = l->data))
				continue;
			if (addr_info_equal(&(m0info->addr), &(sInfo->addr))) {
				guint16 *p, *max;
				guint i = 0;
				GArray *pfx = g_array_new(FALSE, FALSE, 2);
				p = (guint16*) m0info->prefixes;
				max = (guint16*) (m0info->prefixes + m0info->prefixes_size);
				for (; p < max; p++) {
					i++;
					pfx = g_array_append_vals(pfx, (guint8*)p, 1);
				}
				aM1->prefixes = pfx;
				aM1->score = i;
				GRID_DEBUG("aM1 %s, score %d", aM1->addr, aM1->score);
				prefixByMeta1 = g_slist_remove(prefixByMeta1, m0info);
				meta0_info_clean(m0info);

				break;
			}
		}
		struct meta1_assignment_s *m1ref = g_hash_table_lookup(
				context->m1_assign_by_addr, aM1->addr);

		if (m1ref && !m1ref->used) {
			// unref meta1
			aM1->used = FALSE;
			if (aM1->score != 0) {
				// meta1 refer always prefixe
				*unref_m1list = g_slist_prepend(*unref_m1list, aM1);
			}
		} else {
			*working_m1list = g_list_prepend(*working_m1list, aM1);
		}
		g_hash_table_insert(context->working_m1_assign_by_addr,
				strdup(aM1->addr), aM1);
	}

	GRID_TRACE("len working %d, len reste pref %d",
			g_list_length(*working_m1list), g_slist_length(prefixByMeta1));
	guint nb_M1 = g_list_length(*working_m1list) + g_slist_length(prefixByMeta1);

	//defined the average assign score
	if (nb_M1 == 0) {
		GRID_ERROR("No Meta1 available");
		error = NEWERROR(0, "No Meta1 service available");
		goto errorLabel;
	}

	context->avgscore = (CID_PREFIX_COUNT * context->replica) / nb_M1;
	GRID_DEBUG("average meta1 score %d", context->avgscore);

	GList *work = g_list_first(*working_m1list);
	for (; work; work = work->next) {
		struct meta1_assignment_s *aM1 = work->data;
		if (aM1->score > context->avgscore) {
			aM1->available = TRUE;
		}
	}

	GRID_DEBUG("init meta1 list, find %d meta1",
			g_list_length(*working_m1list));
	GRID_DEBUG("init unref meta1 list, find %d meta1",
			g_slist_length(*unref_m1list));

	meta0_utils_list_clean(prefixByMeta1);

errorLabel :
	if (m1_list) {
		g_slist_foreach(m1_list, service_info_gclean, NULL);
		g_slist_free(m1_list);
	}

	return error;
}

static GError*
_unref_meta1(gchar **urls)
{

	GError *error = NULL;
	GSList *prefixByMeta1 = meta0_utils_array_to_list(context->m1_by_prefix_array);
	guint8 *prefix_mask = g_malloc0(8192);

	for(; *urls; urls++) {
		addr_info_t addr;
		GRID_DEBUG("unref url %s", *urls);

		grid_string_to_addrinfo(*urls, &addr);

		GSList *l = prefixByMeta1;
		for (; l; l = l->next) {
			struct meta0_info_s *m0info;
			if (!(m0info = l->data))
				continue;

			if (addr_info_equal(&(m0info->addr), &addr)) {
				guint16 *p, *max;
				p = (guint16*) m0info->prefixes;
				max = (guint16*) (m0info->prefixes + m0info->prefixes_size);
				for (; p < max; p++) {
					if (_is_treat_prefix(prefix_mask, (guint8*)p)) {
						error = NEWERROR(0,
								"prefix %02X%02X managed by two meta1 present in the request",
								((guint8*)p)[0], ((guint8*)p)[1]);
						GRID_WARN("%s", error->message);
						goto errorLabel;
					}
					_treat_prefix(prefix_mask, (guint8*)p);
				}
			}
		}
		struct meta1_assignment_s *aM1 = NULL;

		aM1 = g_hash_table_lookup(context->m1_assign_by_addr, *urls);
		if (!aM1) {
			aM1 = g_malloc0(sizeof(struct meta1_assignment_s));
			aM1->addr = g_strdup(*urls);
			aM1->score = 0;
			aM1->used = FALSE;
			g_hash_table_insert(context->m1_assign_by_addr, strdup(*urls), aM1);
		} else {
			aM1->used = FALSE;
		}
	}

errorLabel :
	meta0_utils_list_clean(prefixByMeta1);
	g_free(prefix_mask);

	return error;
}

static GError*
_check(GList *working_m1list)
{
	GError *error = NULL;

	if (working_m1list) {

		working_m1list = g_list_sort(working_m1list, meta0_assign_sort_by_score);
		struct meta1_assignment_s *hM1 = working_m1list->data;
		struct meta1_assignment_s *lM1 = (g_list_last(working_m1list))->data;
		guint highscore = hM1->score;
		guint lowscore = lM1->score;
		GRID_TRACE("check delta highscore %d, lowscore %d", highscore, lowscore);
		if ((highscore - lowscore) < (context->avgscore * trigger_assignment) / 100) {
			GRID_WARN("New assign not necessary, high score %d, low score %d, average %d",
					highscore, lowscore, context->avgscore);
			error = NEWERROR(0, "New assign not necessary");
			return error;
		}
	}

	if (context->last_assign_time) {
		GRID_TRACE("last time %s",
				g_date_time_format(context->last_assign_time, "%Y-%m-%d %H:%M"));
		GDateTime *currentTime, *ltime;
		currentTime = g_date_time_new_now_local();
		ltime = g_date_time_add_minutes(context->last_assign_time,
				period_between_two_assign);
		GRID_TRACE("currentTime: %s, last time + %d min: %s, comp: %d",
				g_date_time_format(currentTime, "%Y-%m-%d %H:%M"),
				period_between_two_assign,
				g_date_time_format(ltime, "%Y-%m-%d %H:%M"),
				g_date_time_compare(ltime, currentTime));
		if (g_date_time_compare(ltime, currentTime) > 0) {
			GRID_WARN("delay between two meta1 assign not respected. Try later. last date [%s]",
					g_date_time_format(context->last_assign_time, "%Y-%m-%d %H:%M"));
			error = NEWERROR(0,"delay between two meta1 assign not respected. Try later.");
			return error;
		}
	}

	return NULL;
}

/* ----------------------------------------------------------------------------------------*/

static void
_resetContext() {

	if (context->working_m1_assign_by_addr) {
		g_hash_table_destroy(context->working_m1_assign_by_addr);
		context->working_m1_assign_by_addr = NULL;
	}
	if (context->m1_by_prefix_array) {
		meta0_utils_array_clean(context->m1_by_prefix_array);
		context->m1_by_prefix_array = NULL;
	}

	if (context->m1_assign_by_addr) {
		g_hash_table_destroy(context->m1_assign_by_addr);
		context->m1_assign_by_addr = NULL;
	}

	if (context->treat_prefixes) {
		g_free(context->treat_prefixes);
		context->treat_prefixes = NULL;
	}

	context->replica = 0;
	context->avgscore = 0;
}

static GError*
_initContext(struct meta0_backend_s *m0)
{
	GError *error = NULL;

	if (!context) {
		context = g_malloc0(sizeof(struct meta0_assign_context_s));
	} else {
		_resetContext();
	}

	error = meta0_backend_get_all(m0, &(context->m1_by_prefix_array));
	if (error) {
		GRID_ERROR("failed to duplicate meta1 prefix distribution: (%d) %s",
				error->code, error->message);
		return error;
	}

	GPtrArray *meta1_ref = NULL;
	error = meta0_backend_get_all_meta1_ref(m0, &meta1_ref);
	if (error) {
		meta0_utils_array_meta1ref_clean(meta1_ref);
		GRID_ERROR("failed to duplicate meta1 reference count: (%d) %s",
				error->code, error->message);
		return error;
	}
	context->m1_assign_by_addr = _meta1ref_array_to_map(meta1_ref);
	meta0_utils_array_meta1ref_clean(meta1_ref);

	context->working_m1_assign_by_addr = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, _gfree_map_meta0_assign_meta1);

	context->treat_prefixes = g_malloc0(8192);

	context->replica = 0;
	context->avgscore = 0;

	if (context->m1_by_prefix_array->len > 0) {
		gchar **v = context->m1_by_prefix_array->pdata[0];
		if (v != NULL) {
			for (; *v; v++)
				context->replica++;
			if (context->replica > CID_PREFIX_COUNT) {
				return NEWERROR(EINVAL, "Invalid number of replicas [%d]",
						context->replica);
			}
		}
		GRID_DEBUG("replicas %d", context->replica);
	}
	return NULL;
}

/* ----------------------------------------------------------------------------------------*/

GError*
meta0_assign_fill(struct meta0_backend_s *m0, gchar *ns_name, guint replicas,
		gboolean nodist)
{
	GError *error;
	GList *working_m1list = NULL;
	GSList *unref_m1list = NULL;
	GPtrArray *new_meta1ref = NULL;
	guint idx;
	struct meta1_assignment_s *d_aM1;

	GRID_INFO("START filling meta0 database, with %d replicas for each prefix",
			replicas);

	error = _initContext(m0);
	if (error)
		goto errorLabel;
	context->replica = replicas;

	error = _init_assign(ns_name, &working_m1list, &unref_m1list);
	if (error)
		goto errorLabel;

	error = _check(NULL);
	if (error)
		goto errorLabel;

	while (replicas--) {
		for (idx = 0; idx < CID_PREFIX_COUNT; idx++) {
			working_m1list = g_list_sort(working_m1list, meta0_assign_sort_by_score);
			d_aM1 = _select_dest_assign_m1(working_m1list, NULL,
					(guint8*)(&idx), TRUE, nodist);
			if (! d_aM1) {
				error = NEWERROR(0, "Not enough META1 to satisfy constraints "
						"(distance, number). META0 already initiated?");
				goto errorLabel;
			}

			meta0_utils_array_add(context->m1_by_prefix_array,
					(guint8*)(&idx), d_aM1->addr);

			_increase_score(d_aM1);
		}
	}

	new_meta1ref = _updated_meta1ref();
	error = meta0_backend_assign(m0, context->m1_by_prefix_array, new_meta1ref, TRUE);
	if ( error ) {
		GRID_ERROR("Failed to update database: (%d) %s", error->code, error->message);
		goto errorLabel;
	}

	context->last_assign_time = g_date_time_new_now_local();

errorLabel :
	_resetContext();
	if (new_meta1ref) {
		meta0_utils_array_meta1ref_clean(new_meta1ref);
	}
	if (working_m1list) {
		g_list_free(working_m1list);
		working_m1list = NULL;
	}
	if (unref_m1list) {
		g_slist_free(unref_m1list);
		unref_m1list = NULL;
	}
	GRID_INFO("END FILL");

	return error;
}

GError*
meta0_assign_prefix_to_meta1(struct meta0_backend_s *m0, gchar *ns_name, gboolean nocheck)
{
	// GET meta1 list from conscience
	GList *working_m1list = NULL;
	GSList *unref_m1list = NULL;
	GError *error;
	GPtrArray *new_meta1ref = NULL;

	GRID_INFO("START Assign prefix");

	error = _initContext(m0);
	if (error) {
		goto errorLabel;
	}

	// build working list , list sorted by score
	error = _init_assign(ns_name, &working_m1list, &unref_m1list);
	if (error) {
		goto errorLabel;
	}
	if (nocheck) {
		error = _check(working_m1list);
		if (error) {
			goto errorLabel;
		}
	}

	error = _assign(working_m1list, unref_m1list);
	if (error) {
		goto errorLabel;
	}

	new_meta1ref = _updated_meta1ref();
	error = meta0_backend_assign(m0, context->m1_by_prefix_array, new_meta1ref, FALSE);
	if ( error ) {
		GRID_ERROR("Failed to update database: (%d) %s", error->code, error->message);
		goto errorLabel;
	}
	context->last_assign_time = g_date_time_new_now_local();

errorLabel :
	_resetContext();
	if (new_meta1ref) {
		meta0_utils_array_meta1ref_clean(new_meta1ref);
	}
	if (working_m1list) {
		g_list_free(working_m1list);
		working_m1list = NULL;
	}
	if (unref_m1list) {
		g_slist_free(unref_m1list);
		unref_m1list = NULL;
	}
	GRID_INFO("END ASSIGN");

	return error;
}

GError*
meta0_assign_disable_meta1(struct meta0_backend_s *m0, gchar *ns_name,
		char **m1urls, gboolean nocheck)
{
	GList *working_m1list = NULL;
	GSList *unref_m1list = NULL;
	GPtrArray *new_meta1ref = NULL;
	GError *error;

	gchar * urls = g_strjoinv(" ", m1urls);
	GRID_INFO("START disable meta1 %s", urls);
	g_free(urls);

	error = _initContext(m0);
	if (error)
		goto errorLabel;

	if (nocheck) {
		error = _check(NULL);
		if (error)
			goto errorLabel;
	}

	error = _unref_meta1(m1urls);
	if (error)
		goto errorLabel;

	error = _init_assign(ns_name, &working_m1list, &unref_m1list);
	if (error)
		goto errorLabel;

	error = _assign(working_m1list, unref_m1list);
	if (error)
		goto errorLabel;

	new_meta1ref = _updated_meta1ref();
	error = meta0_backend_assign(m0, context->m1_by_prefix_array, new_meta1ref, FALSE);
	if (error) {
		GRID_ERROR("Failed to update database: (%d) %s", error->code, error->message);
		goto errorLabel;
	}

	context->last_assign_time = g_date_time_new_now_local();

errorLabel :
	_resetContext();
	if (new_meta1ref) {
		meta0_utils_array_meta1ref_clean(new_meta1ref);
	}
	if (working_m1list) {
		g_list_free(working_m1list);
		working_m1list = NULL;
	}
	if (unref_m1list) {
		g_slist_free(unref_m1list);
		unref_m1list = NULL;
	}
	GRID_INFO("END DISABLE META1");

	return error;
}
