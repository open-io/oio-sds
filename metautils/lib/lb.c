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
# define G_LOG_DOMAIN "grid.lb"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "./metautils.h"
#include "./resolv.h"
#include "./lb.h"

typedef guint32 srv_weight_t;
typedef guint32 srv_score_t;

struct grid_lb_s
{
	gchar ns[64];
	gchar srvtype[64];
	void (*use_hook) (void);

	GMutex *lock;
	guint64 version;

	GPtrArray *gpa;
	GHashTable *id_by_addr;

	GArray *sorted_by_score;
	guint32 sum_scored;

	GArray *sorted_by_weight;
	guint32 sum_weighted;
};

struct weight_slot_s
{
	guint index;
	srv_weight_t weight;
	guint32 sum;
};

struct score_slot_s
{
	guint index;
	srv_score_t score;
	guint32 sum;
};

struct grid_lb_iterator_s
{
	struct grid_lb_s *lb;
	guint64 version;
	enum {
		LBIT_SINGLE=1,
		LBIT_SHARED,
		LBIT_RR,
		LBIT_WRR,
		LBIT_SRR,
		LBIT_RAND,
		LBIT_WRAND,
		LBIT_SRAND
	} type;
	union {
		struct {
			guint next_idx;
		} single;

		struct {
			guint next_idx;
		} rr;
		struct {
			guint next_idx;
			srv_weight_t current;
		} wrr;
		struct {
			guint next_idx;
			srv_score_t current;
		} srr;

		struct {
			struct grid_lb_iterator_s *sub;

			service_filter* hook_filter;
			gpointer hook_data;
			GDestroyNotify cleanup;
		} shared;
	} internals;
};


/* Various helpers */

static const gchar *
service_info_get_tag_value(const struct service_info_s *si, const gchar *n,
		const gchar *def)
{
	struct service_tag_s *tag;

	if (!si || !si->tags)
		return def;
	if (!(tag = service_info_get_tag(si->tags, n)))
		return def;
	if (tag->type == STVT_STR)
		return tag->value.s;
	if (tag->type == STVT_BUF)
		return tag->value.buf;
	return def;
}

static const gchar *
service_info_get_rawx_location(const struct service_info_s *si, const gchar *d)
{
	return service_info_get_tag_value(si, NAME_TAGNAME_RAWX_LOC, d);
}

static guint
_distance_loc(const gchar *loc1, const gchar *loc2)
{
	/* The arrays of tokens. */
	gchar **split_loc1, **split_loc2;
	/* Used to iterate over the arrays of tokens. */
	gchar **iter_tok1, **iter_tok2;
	/* The current tokens. */
	gchar *cur_tok1, *cur_tok2;
	/* Stores the greatest number of tokens in both location names. */
	guint num_tok = 0U;
	/* Number of the current token. */
	guint cur_iter = 0U;
	/* TRUE if a different token was found. */
	gboolean found_diff = FALSE;
	/* Distance between 2 tokens. */
	guint token_dist;

	if ((!loc1 || !*loc1) && (!loc2 || !*loc2))
		return 1U;

	split_loc1 = g_strsplit(loc1, ".", 0);
	split_loc2 = g_strsplit(loc2, ".", 0);

	iter_tok1 = split_loc1;
	iter_tok2 = split_loc2;

	cur_tok2 = *iter_tok2;

	while ((cur_tok1 = *iter_tok1++)) {
		num_tok++;
		if (cur_tok2 && (cur_tok2 = *iter_tok2++) && !found_diff) {
			cur_iter++;
			/* if both tokens are equal, continue */
			/* else set the found_diff flag to TRUE, keep the value of cur_iter and continue to set num_tok */
			if (g_strcmp0(cur_tok1, cur_tok2))
				found_diff = TRUE;
		}
	}

	/* if loc2 has more tokens than loc1, increase num_tok to this value */
	if (cur_tok2) {
		while (*iter_tok2++)
			num_tok++;
	}

	/* Frees the arrays of tokens. */
	g_strfreev(split_loc1);
	g_strfreev(split_loc2);

	token_dist = num_tok - cur_iter + 1;

	/* If the token distance is 1 and the last tokens are equal (ie both locations are equal) -> return 0. */
	/* If the token distance is 1 and the last tokens are different -> return 1. */
	/* If the token distance is > 1, then return 2^(token_dist). */
	return token_dist > 1U ? 1U << (token_dist - 1U) : (found_diff ? 1U : 0U);
}

static guint
_distance_si(struct service_info_s *si0, struct service_info_s *si1)
{
	return _distance_loc(service_info_get_rawx_location(si0, NULL),
			service_info_get_rawx_location(si1, NULL));
}

static inline gint
_get_index_by_addr(struct grid_lb_s *lb, const addr_info_t *ai)
{
	gpointer p;

	p = g_hash_table_lookup(lb->id_by_addr, ai);
	if (!p)
		return -1;

	return GPOINTER_TO_UINT(p) - 1;
}

static inline void
_save_index_for_addr(struct grid_lb_s *lb, addr_info_t *ai,
		guint idx)
{
	gpointer p;

	idx ++;

	p = GUINT_TO_POINTER(idx);
	g_hash_table_insert(lb->id_by_addr, ai, p);
}

static inline srv_weight_t
si_get_weight(struct service_info_s *si)
{
	(void) si;
	/*return rand() % 100;*/
	return 1;
}

static gint
sort_slots_by_weight(gconstpointer p1, gconstpointer p2)
{
	return (p1 == p2) ? 0 : ((struct weight_slot_s*)p2)->weight
		- ((struct weight_slot_s*)p1)->weight;
}

static gint
sort_slots_by_score(gconstpointer p1, gconstpointer p2)
{
	return (p1 == p2) ? 0 : ((struct score_slot_s*)p2)->score
		- ((struct score_slot_s*)p1)->score;
}


/* Pool features */

struct grid_lb_s*
grid_lb_init(const gchar *ns, const gchar *srvtype)
{
	struct grid_lb_s *lb;

	lb = g_malloc0(sizeof(*lb));
	if (!lb)
		return NULL;

	g_strlcpy(lb->ns, ns, sizeof(lb->ns));
	g_strlcpy(lb->srvtype, srvtype, sizeof(lb->srvtype));
	lb->version = 1;
	lb->use_hook = NULL;
	lb->lock = g_mutex_new();
	lb->gpa = g_ptr_array_new();

	lb->id_by_addr = g_hash_table_new(
			addr_info_hash, addr_info_equal);

	lb->sorted_by_score = g_array_new(FALSE, FALSE,
			sizeof(struct score_slot_s));
	lb->sorted_by_weight = g_array_new(FALSE, FALSE,
			sizeof(struct weight_slot_s));

	return lb;
}

static inline void
grid_lb_flush(struct grid_lb_s *lb)
{
	guint i;
	GPtrArray *gpa;

	if (!lb)
		return;
	
	/* Flush the 'links' to the services */
	g_hash_table_steal_all(lb->id_by_addr);
	g_array_set_size(lb->sorted_by_score, 0);
	g_array_set_size(lb->sorted_by_weight, 0);

	/* Now flush the services themselves */
	gpa = lb->gpa;
	for (i=gpa->len; i>0 ;i--) {
		struct service_info_s *si = gpa->pdata[i-1];
		if (!si)
			continue;
		service_info_clean(si);
	}
	
	g_ptr_array_set_size(gpa, 0);
}

void
grid_lb_clean(struct grid_lb_s *lb)
{
	if (!lb)
		return;

	if (lb->lock) {
		g_mutex_lock(lb->lock);
		g_mutex_unlock(lb->lock);
	}

	grid_lb_flush(lb);

	if (lb->gpa)
		g_ptr_array_free(lb->gpa, TRUE);

	if (lb->id_by_addr)
		g_hash_table_destroy(lb->id_by_addr);

	if (lb->sorted_by_weight)
		g_array_free(lb->sorted_by_weight, TRUE);

	if (lb->sorted_by_score)
		g_array_free(lb->sorted_by_score, TRUE);

	if (lb->lock)
		g_mutex_free(lb->lock);

	g_free(lb);
}

void
grid_lb_reload(struct grid_lb_s *lb, service_provider_f provide)
{
	guint32 sum;
	guint i;
	struct service_info_s *si = NULL;
	GPtrArray *gpa;

	if (!lb)
		return;

	g_mutex_lock(lb->lock);

	/* Soft cleansing of the services and their references */
	grid_lb_flush(lb);

	/* Reload the services */
	gpa = lb->gpa;
	while (provide(&si)) {
		if (si) {
			if (si->score.value > 0)
				g_ptr_array_add(gpa, si);
			else
				service_info_clean(si);
		}
	}

	/* Rebuild the links to the services */
	for (i=gpa->len; i>0 ;i--) {
		struct service_info_s *si0 = gpa->pdata[i - 1];

		struct score_slot_s score;
		score.index = i - 1;
		score.score = si0->score.value;
		lb->sorted_by_score = g_array_append_vals(lb->sorted_by_score, &score, 1);

		struct weight_slot_s weight;
		weight.index = i - 1;
		weight.weight = si_get_weight(si0);
		lb->sorted_by_weight = g_array_append_vals(lb->sorted_by_weight, &weight, 1);

		_save_index_for_addr(lb, &(si0->addr), i - 1);
	}

	/* Computes the incremental sum of the weight-sorted set */
	g_array_sort(lb->sorted_by_weight, sort_slots_by_weight);

	sum = 0;
	for (i=lb->sorted_by_weight->len; i>0 ;i--) {
		struct weight_slot_s *slot = &g_array_index(lb->sorted_by_weight, struct weight_slot_s, i-1);
		slot->sum = sum;
		sum += slot->weight;
	}
	lb->sum_weighted = sum;

	/* Computes the incremental sum of the score-sorted set */
	g_array_sort(lb->sorted_by_score, sort_slots_by_score);

	sum = 0;
	for (i=lb->sorted_by_score->len; i>0 ;i--) {
		struct score_slot_s *slot = &g_array_index(lb->sorted_by_score, struct score_slot_s, i-1);
		slot->sum = sum;
		sum += slot->score;
	}
	lb->sum_scored = sum;

	/* Let the iterators manage our fresh load-balancer */
	++ lb->version;

	g_mutex_unlock(lb->lock);
}

gboolean
grid_lb_is_addr_available(struct grid_lb_s *lb, const struct addr_info_s *ai)
{
	gboolean rc;

	gboolean check(void) {
		struct service_info_s *local_si;
		gint idx = _get_index_by_addr(lb, ai);
		if (idx < 0)
			return FALSE;

		local_si = lb->gpa->pdata[idx];
		if (!local_si)
			return FALSE;
		return local_si->score.value > 0;
	}

	g_assert(lb != NULL);
	g_assert(ai != NULL);

	g_mutex_lock(lb->lock);
	rc = check();
	g_mutex_unlock(lb->lock);
	return rc;
}

gboolean
grid_lb_is_srv_available(struct grid_lb_s *lb, const struct service_info_s *si)
{
	g_assert(si != NULL);
	g_assert(lb != NULL);

	g_assert(!g_ascii_strncasecmp(si->type, lb->srvtype, sizeof(si->type)));
	g_assert(!g_ascii_strncasecmp(si->ns_name, lb->ns, sizeof(si->ns_name)));

	return grid_lb_is_addr_available(lb, &(si->addr));
}

gboolean
grid_lb_iterator_is_url_available(struct grid_lb_iterator_s *iter,
		const gchar *url)
{
	addr_info_t ai;

	if (!url) {
		errno = EINVAL;
		return FALSE;
	}

	if (!grid_string_to_addrinfo(url, NULL, &ai))
		return FALSE;

	return grid_lb_iterator_is_addr_available(iter, &ai);
}

gsize
grid_lb_count(struct grid_lb_s *lb)
{
	if (!lb || !lb->gpa)
		return 0;
	gsize s = lb->gpa->len;
	return s;
}

/* Pool iterator constructors */

struct grid_lb_iterator_s*
grid_lb_iterator_share(struct grid_lb_iterator_s *sub,
		service_filter* custom_filter, gpointer u,
		GDestroyNotify cleanup)
{
	struct grid_lb_iterator_s *iter;

	g_assert(sub != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = sub->lb;
	iter->version = sub->version;
	iter->type = LBIT_SHARED;
	iter->internals.shared.sub = sub;
	iter->internals.shared.hook_filter = custom_filter;
	iter->internals.shared.hook_data = u;
	iter->internals.shared.cleanup = cleanup;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_single_run(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_SINGLE;
	iter->internals.rr.next_idx = 0;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_round_robin(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_RR;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_weighted_round_robin(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_WRR;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_scored_round_robin(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_SRR;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_random(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_RAND;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_weighted_random(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_WRAND;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_scored_random(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(*iter));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_SRAND;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_init(struct grid_lb_s *lb, const gchar *type)
{
	if (type && *type) {
		if (!g_ascii_strcasecmp(type, "WRR"))
			return grid_lb_iterator_weighted_round_robin(lb);
		if (!g_ascii_strcasecmp(type, "SRR"))
			return grid_lb_iterator_scored_round_robin(lb);
		if (!g_ascii_strcasecmp(type, "RAND"))
			return grid_lb_iterator_random(lb);
		if (!g_ascii_strcasecmp(type, "WRAND"))
			return grid_lb_iterator_weighted_random(lb);
		if (!g_ascii_strcasecmp(type, "SRAND"))
			return grid_lb_iterator_scored_random(lb);
		if (!g_ascii_strcasecmp(type, "SINGLE"))
			return grid_lb_iterator_single_run(lb);
	}
	return grid_lb_iterator_round_robin(lb);
}

gboolean
grid_lb_iterator_is_srv_available(struct grid_lb_iterator_s *iter,
		const struct service_info_s *si)
{
	g_assert(iter != NULL);
	return grid_lb_is_srv_available(iter->lb, si);
}

gboolean grid_lb_iterator_is_addr_available(struct grid_lb_iterator_s *iter,
		const struct addr_info_s *ai)
{
	g_assert(iter != NULL);
	return grid_lb_is_addr_available(iter->lb, ai);
}

/* Pool iterators runner */

static inline struct service_info_s*
_get_modulo(struct grid_lb_s *lb, guint idx)
{
	register struct service_info_s *si = NULL;
	guint len;

	if (0 != (len = lb->gpa->len))
		si = service_info_dup(lb->gpa->pdata[idx % len]);

	return si;
}

static inline gboolean
__next_SINGLE(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter, struct service_info_s **si)
{
	guint max;
	struct service_info_s *result = NULL;

	g_mutex_lock(lb->lock);
	max = lb->gpa->len;
	if (iter->version == lb->version && max > 0) {
		if (iter->internals.single.next_idx < max)
			result = _get_modulo(lb, iter->internals.single.next_idx ++);
	}
	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline gboolean
__next_RR(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter, struct service_info_s **si)
{
	struct service_info_s *result = NULL;

	g_mutex_lock(lb->lock);
	if (lb->gpa->len > 0)
		result = _get_modulo(lb, iter->internals.rr.next_idx ++);
	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline gboolean
__next_WRR(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter, struct service_info_s **si)
{
	guint ridx;
	struct weight_slot_s *slot;
	struct service_info_s *result = NULL;

	inline void reset(void) {
		iter->internals.wrr.next_idx = 0;
		slot = &g_array_index(lb->sorted_by_weight, struct weight_slot_s, 0);
		iter->internals.wrr.current = slot->weight;
	}
	inline void decrement(void) {
		iter->internals.wrr.next_idx = 0;
		if (! --iter->internals.wrr.current)
			reset();
	}

	g_mutex_lock(lb->lock);
	if (lb->gpa->len > 0) {
		if (iter->internals.wrr.current == 0)
			reset();
		else if (iter->internals.wrr.next_idx >= lb->sorted_by_weight->len)
			decrement();
		else {
			slot = &g_array_index(lb->sorted_by_weight, struct weight_slot_s, iter->internals.wrr.next_idx); 
			if (iter->internals.wrr.current > slot->weight)
				decrement();
		}

		ridx = iter->internals.wrr.next_idx ++;
		slot = &g_array_index(lb->sorted_by_weight, struct weight_slot_s, ridx);
		result = _get_modulo(lb, slot->index);
	}
	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline gboolean
__next_SRR(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter, struct service_info_s **si)
{
	guint ridx;
	struct score_slot_s *slot;
	struct service_info_s *result = NULL;

	inline void reset(void) {
		iter->internals.srr.next_idx = 0;
		slot = &g_array_index(lb->sorted_by_score, struct score_slot_s, 0);
		iter->internals.srr.current = slot->score;
	}
	inline void decrement(void) {
		iter->internals.srr.next_idx = 0;
		if (! --iter->internals.srr.current)
			reset();
	}

	g_mutex_lock(lb->lock);
	if (lb->gpa->len > 0) {
		if (iter->internals.srr.current == 0)
			reset();
		else if (iter->internals.srr.next_idx >= lb->sorted_by_score->len)
			decrement();
		else {
			slot = &g_array_index(lb->sorted_by_score, struct score_slot_s, iter->internals.srr.next_idx); 
			if (iter->internals.srr.current > slot->score)
				decrement();
		}

		ridx = iter->internals.srr.next_idx ++;
		slot = &g_array_index(lb->sorted_by_score, struct score_slot_s, ridx);
		result = _get_modulo(lb, slot->index);
	}
	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline gboolean
__next_RAND(struct grid_lb_s *lb, struct service_info_s **si)
{
	struct service_info_s *result = NULL;
	guint idx = rand();

	g_mutex_lock(lb->lock);
	result = _get_modulo(lb,idx);
	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline guint32
guint32_absdiff(guint32 i0, guint32 i1)
{
	return (i0 > i1) ? (i0 - i1) : (i1 - i0);
}

static inline gboolean
__next_WRAND(struct grid_lb_s *lb, struct service_info_s **si)
{
	GArray *ga;
	struct weight_slot_s *slot;
	struct service_info_s *result = NULL;
	guint32 needle;
	guint ridx;

	inline guint dichotomic_search(guint start, guint end) {
		guint32 middle_sum;
		guint middle;

		middle = (start + end) / 2;
		slot = &g_array_index(ga, struct weight_slot_s, middle);
		middle_sum = slot->sum;

		if ((end - start) <= 1) {
			guint32 diff_start, diff_end;
			diff_start = guint32_absdiff(middle_sum, g_array_index(ga, struct weight_slot_s, start).sum);
			diff_end = guint32_absdiff(middle_sum, g_array_index(ga, struct weight_slot_s, end).sum);
			return (diff_start < diff_end) ? start : end;
		}
		if (needle < middle_sum)
			return dichotomic_search(middle, end);
		return dichotomic_search(start, middle);
	}

	needle = rand();

	g_mutex_lock(lb->lock);
	if (lb->gpa->len > 0) {
		needle = needle % lb->sum_weighted;
		ga = lb->sorted_by_weight;
		ridx = dichotomic_search(0, ga->len);
		slot = &g_array_index(ga, struct weight_slot_s, ridx);
		result = _get_modulo(lb, slot->index);
	}
	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline gboolean
__next_SRAND(struct grid_lb_s *lb, struct service_info_s **si)
{
	GArray *ga;
	struct score_slot_s *slot;
	struct service_info_s *result = NULL;
	guint32 needle;
	guint ridx;

	inline guint dichotomic_search(guint start, guint end) {
		guint32 middle_sum;
		guint middle;

		middle = (start + end) / 2;
		slot = &g_array_index(ga, struct score_slot_s, middle);
		middle_sum = slot->sum;

		if ((end - start) <= 1) {
			guint32 diff_start, diff_end;
			diff_start = guint32_absdiff(middle_sum, g_array_index(ga, struct score_slot_s, start).sum);
			diff_end = guint32_absdiff(middle_sum, g_array_index(ga, struct score_slot_s, end).sum);
			return (diff_start < diff_end) ? start : end;
		}
		if (needle <= middle_sum)
			return dichotomic_search(middle, end);
		return dichotomic_search(start, middle);
	}

	needle = rand();

	g_mutex_lock(lb->lock);

	if (lb->gpa->len > 0) {
		needle = needle % lb->sum_scored;
		ga = lb->sorted_by_score;
		ridx = dichotomic_search(0, ga->len);
		slot = &g_array_index(ga, struct score_slot_s, ridx);
		result = _get_modulo(lb, slot->index);
	}

	g_mutex_unlock(lb->lock);

	if (!result)
		return FALSE;
	*si = result;
	return TRUE;
}

static inline gboolean
__next_SHARED(struct grid_lb_iterator_s *iter, struct service_info_s **si, int ttl)
{
	while (ttl-- >= 0) {
		struct service_info_s *tmp = NULL;

		if (!grid_lb_iterator_next(iter->internals.shared.sub, &tmp, 300))
			return FALSE;

		if (!iter->internals.shared.hook_filter ||
				iter->internals.shared.hook_filter(tmp, iter->internals.shared.hook_data)) {
			*si = tmp;
			return TRUE;
		}
		service_info_clean(tmp);
		tmp = NULL;
	}

	return FALSE;
}

gboolean
grid_lb_iterator_next(struct grid_lb_iterator_s *iter, struct service_info_s **si, int ttl)
{
	struct grid_lb_s *lb;

	if (!iter || !si)
		return FALSE;

	lb = iter->lb;
	g_assert(lb != NULL);

	if (lb->use_hook)
		lb->use_hook();

	switch (iter->type) {
		case LBIT_SINGLE:
			return __next_SINGLE(lb, iter, si);
		case LBIT_RR:
			return __next_RR(lb, iter, si);
		case LBIT_WRR:
			return __next_WRR(lb, iter, si);
		case LBIT_SRR:
			return __next_SRR(lb, iter, si);
		case LBIT_RAND:
			return __next_RAND(lb, si);
		case LBIT_WRAND:
			return __next_WRAND(lb, si);
		case LBIT_SRAND:
			return __next_SRAND(lb, si);
		case LBIT_SHARED:
			return __next_SHARED(iter, si, ttl);
	}

	g_assert_not_reached();
	return FALSE;
}

void
grid_lb_iterator_clean(struct grid_lb_iterator_s *iter)
{
        if (!iter)
                return;
        if (iter->type == LBIT_SHARED) {
                if (iter->internals.shared.hook_data && iter->internals.shared.cleanup)
                        iter->internals.shared.cleanup(iter->internals.shared.hook_data);
        }
        memset(iter, 0, sizeof(*iter));
        g_free(iter);
}

static GPtrArray*
gtree_to_gpa(GTree *t)
{
	gboolean run_move(gpointer k, gpointer v, gpointer u) {
		(void) k;
		g_ptr_array_add(u, v);
		return FALSE;
	}
	GPtrArray *tmp = g_ptr_array_sized_new(g_tree_nnodes(t)+1);
	g_tree_foreach(t, run_move, tmp);
	g_tree_destroy(t);
	return tmp;
}

static void**
gpa_to_array(GPtrArray *gpa)
{
	g_assert(gpa != NULL);
	if (!gpa->len || NULL != gpa->pdata[gpa->len - 1])
		g_ptr_array_add(gpa, NULL);
	return g_ptr_array_free(gpa, FALSE);
}

gboolean
grid_lb_iterator_next_set(struct grid_lb_iterator_s *iter,
		struct service_info_s ***result, struct lb_next_opt_s *opt)
{
	gboolean run_clean(gpointer k, gpointer v, gpointer u) {
		(void) k;
		(void) u;
		service_info_clean(v);
		return FALSE;
	}
	gint cmp_addr(gconstpointer a, gconstpointer b, gpointer user_data) {
		(void) user_data;
		return addr_info_compare(a, b);
	}
	gint cmp_ptr(gconstpointer a, gconstpointer b, gpointer user_data) {
		(void) user_data;
		return (a < b) ? -1 : (a > b ? 1 : 0);
	}

	if (!iter || !result || !opt || !opt->max)
		return FALSE;
	if ((!opt->dupplicates) && opt->max > grid_lb_count(iter->lb))
		return FALSE;

	GTree *polled = NULL;
	gsize limit = grid_lb_count(iter->lb);

	if (!opt->dupplicates)
		polled = g_tree_new_full(cmp_addr, NULL, NULL, NULL);
	else
		polled = g_tree_new_full(cmp_ptr, NULL, NULL, NULL);

	while (opt->max > (guint)g_tree_nnodes(polled)) {
		struct service_info_s *old = NULL, *si = NULL;

		// Tries to poll a new service
		if (limit <= 0 || !grid_lb_iterator_next(iter, &si, 300)) {
			g_tree_foreach(polled, run_clean, NULL);
			g_tree_destroy(polled);
			return FALSE;
		}

		// Check the service matches the distance requirements with the others
		if (opt->reqdist > 1) {
			guint mindist = G_MAXUINT;
			gboolean runner(gpointer k, gpointer v, gpointer u) {
				guint d;
				(void) k;
				if (mindist > (d = _distance_si(v, u)))
					mindist = d;
				return (mindist < opt->reqdist) ? TRUE : FALSE;
			}
			g_tree_foreach(polled, runner, si);
			if (mindist < opt->reqdist) { // not enough distance with at least one other
				service_info_clean(si);
				-- limit;
				continue;
			}
		}

		// Ok, store the service
		if (!(old = g_tree_lookup(polled, &(si->addr)))) {
			g_tree_replace(polled, &(si->addr), si);
		}
		else {
			service_info_swap(si, old);
			service_info_clean(si);
		}
	}

	*result = (struct service_info_s**) gpa_to_array(gtree_to_gpa(polled));
	return TRUE;
}

