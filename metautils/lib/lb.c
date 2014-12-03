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

#include <math.h>

#include <glib.h>

#include <json.h>

#include "./metautils.h"
#include "./resolv.h"
#include "./lb.h"
#include "./storage_policy.h"

#define BOOLNAME(b) ((b)?"TRUE":"FALSE")
#define IS(S) !g_ascii_strcasecmp(type, (S))
#define SLOT(P) ((struct score_slot_s*)P)

typedef guint32 srv_weight_t;
typedef guint32 srv_score_t;

struct grid_lb_s
{
	gchar ns[64];
	gchar srvtype[64];

	gdouble shorten_ratio;
	gboolean standard_deviation;
	gint reset_delay;

	void (*use_hook) (void);

	GStaticRecMutex lock;
	guint64 version;

	GPtrArray *gpa;
	GHashTable *id_by_addr;

	GArray *sorted_by_score;
	guint32 sum_scored;
	guint32 size_max;
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
	enum glbi_type_e {
		LBIT_SINGLE=1,
		LBIT_SHARED,
		LBIT_RR,
		LBIT_WRR,
		LBIT_RAND,
		LBIT_WRAND
	} type;
	union {
		struct {
			guint next_idx;
		} single;

		struct {
			guint next_idx;
			guint next_idx_global;
		} rr;

		// please keep same field order as rr
		struct {
			guint next_idx;
			guint next_idx_global;
			srv_score_t current;
			gint last_reset;
		} srr;

		struct {
			struct grid_lb_iterator_s *sub;
		} shared;
	} internals;
};

struct grid_lbpool_s
{
	gchar ns[LIMIT_LENGTH_NSNAME];
	GStaticRWLock rwlock;
	GTree *pools;
	GTree *iterators;
};


/* Various helpers */

static inline enum glbi_type_e
_get_effective_type(struct grid_lb_iterator_s *it)
{
	if (unlikely(NULL == it))
		return 0;
	if (it->type == LBIT_SHARED)
		return _get_effective_type(it->internals.shared.sub);
	return it->type;
}

static inline struct service_info_s*
_get_raw(struct grid_lb_s *lb, guint idx)
{
	register guint len;
	return !(len = lb->gpa->len) ? NULL
		: service_info_dup(lb->gpa->pdata[idx % len]);
}

static inline struct service_info_s*
_get_by_score(struct grid_lb_s *lb, guint idx)
{
	if (!lb->size_max)
		return NULL;

	register struct score_slot_s *slot;
	slot = &g_array_index(lb->sorted_by_score, struct score_slot_s,
			idx % lb->size_max);
	return _get_raw(lb, slot->index);
}

static inline struct service_info_s*
_get_by_score_no_shorten(struct grid_lb_s *lb, guint idx)
{
	if (!lb->gpa->len)
		return NULL;

	register struct score_slot_s *slot;
	slot = &g_array_index(lb->sorted_by_score, struct score_slot_s,
			idx % lb->gpa->len);
	return _get_raw(lb, slot->index);
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
_save_index_for_addr(struct grid_lb_s *lb, addr_info_t *ai, guint idx)
{
	gpointer p;

	idx ++;

	p = GUINT_TO_POINTER(idx);
	g_hash_table_insert(lb->id_by_addr, ai, p);
}

static gint
sort_slots_by_score(gconstpointer p1, gconstpointer p2)
{
	return CMP(SLOT(p2)->score, SLOT(p1)->score);
}


/* Pool features ----------------------------------------------------------- */

static inline void
grid_lb_lock(struct grid_lb_s *lb)
{
	g_static_rec_mutex_lock(&(lb->lock));
}

static inline void
grid_lb_unlock(struct grid_lb_s *lb)
{
	g_static_rec_mutex_unlock(&(lb->lock));
}

void
grid_lb_set_SD_shortening(struct grid_lb_s *lb, gboolean on)
{
	if (lb)
		lb->standard_deviation = on;
}

void
grid_lb_set_shorten_ratio(struct grid_lb_s *lb, gdouble ratio)
{
	if (lb)
		lb->shorten_ratio = CLAMP(ratio, 0.001, 1.001);
}

struct grid_lb_s*
grid_lb_init(const gchar *ns, const gchar *srvtype)
{
	struct grid_lb_s *lb;

	lb = g_malloc0(sizeof(struct grid_lb_s));
	if (!lb)
		return NULL;

	g_strlcpy(lb->ns, ns, sizeof(lb->ns));
	g_strlcpy(lb->srvtype, srvtype, sizeof(lb->srvtype));
	lb->shorten_ratio = 1.001;
	lb->standard_deviation = FALSE;
	lb->version = 1;
	lb->use_hook = NULL;
	g_static_rec_mutex_init(&(lb->lock));
	lb->gpa = g_ptr_array_new();

	lb->id_by_addr = g_hash_table_new(
			addr_info_hash, addr_info_equal);

	lb->sorted_by_score = g_array_new(TRUE, TRUE,
			sizeof(struct score_slot_s));
	return lb;
}

static void
_lb_flush(struct grid_lb_s *lb)
{
	guint i;
	GPtrArray *gpa;

	if (!lb)
		return;

	/* Flush the 'links' to the services */
	g_hash_table_steal_all(lb->id_by_addr);
	g_array_set_size(lb->sorted_by_score, 0);

	/* Now flush the services themselves */
	gpa = lb->gpa;
	for (i=gpa->len; i>0 ;i--) {
		struct service_info_s *si = gpa->pdata[i-1];
		if (!si)
			continue;
		service_info_clean(si);
	}

	g_ptr_array_set_size(gpa, 0);
	lb->sum_scored = 0;
	lb->size_max = 0;
}

void
grid_lb_clean(struct grid_lb_s *lb)
{
	if (!lb)
		return;

	_lb_flush(lb);

	if (lb->gpa)
		g_ptr_array_free(lb->gpa, TRUE);

	if (lb->id_by_addr)
		g_hash_table_destroy(lb->id_by_addr);

	if (lb->sorted_by_score)
		g_array_free(lb->sorted_by_score, TRUE);

	g_static_rec_mutex_free(&(lb->lock));

	g_free(lb);
}

static void
_lb_consume_provider(struct grid_lb_s *lb, service_provider_f provide)
{
	for (struct service_info_s *si=NULL; provide(&si) ;si=NULL) {
		if (!si)
			continue;
		if (si->score.value > 0)
			g_ptr_array_add(lb->gpa, si);
		else
			service_info_clean(si);
	}
}

static void
_lb_relink_services(struct grid_lb_s *lb)
{
	struct service_info_s **siv, *si;
	struct score_slot_s score;

	siv = (struct service_info_s**) lb->gpa->pdata;
	for (guint i=lb->gpa->len; i>0 ;) {
		si = siv[--i];
		score.index = i;
		score.score = si->score.value;
		lb->sorted_by_score = g_array_append_vals(lb->sorted_by_score, &score, 1);
		_save_index_for_addr(lb, &si->addr, i);
	}

	g_assert(lb->sorted_by_score->len == lb->gpa->len);
	g_array_sort(lb->sorted_by_score, sort_slots_by_score);
}

static void
_lb_cumulate_scores_sum(struct grid_lb_s *lb)
{
	guint32 sum = 0;
	struct score_slot_s *slot;

	for (guint i=lb->sorted_by_score->len; i>0 ;--i) {
		slot = &g_array_index(lb->sorted_by_score, struct score_slot_s, i-1);
		slot->sum = (sum += slot->score);
	}

	lb->sum_scored = sum;
}

static guint32
_compute_min_score_by_SD(struct grid_lb_s *lb)
{
	guint32 max;
	guint64 x, ex=0, ex2=0;

	register guint count = lb->sorted_by_score->len;
	max = g_array_index(lb->sorted_by_score, struct score_slot_s, 0).score;
	for (register guint i=0; i < count ;++i) {
		x = g_array_index(lb->sorted_by_score, struct score_slot_s, i).score;

		ex += x;
		ex2 += x * x;
	}
	ex = ex / count;
	ex2 = ex2 / count;

	x = ex2 - (ex * ex); // x <- variance
	x = ceil(sqrt((gdouble)x)); // x <- ecart type
	x = ex - x; // x <- average - ecart type (pire score admissible)
	return FUNC_CLAMP(x, 1, max);
}

static guint
_compute_size_greater(struct grid_lb_s *lb, guint32 score)
{
	// XXX can be quicker with a bsearch()
	register guint max = lb->sorted_by_score->len;
	for (register guint i=0; i < max ;++i) {
		if (score > g_array_index(lb->sorted_by_score, struct score_slot_s, i).score)
			return i;
	}
	return max;
}

static guint
_compute_size_shortened_by_SD(struct grid_lb_s *lb)
{
	if (!lb->standard_deviation)
		return lb->sorted_by_score->len;
	return _compute_size_greater(lb, _compute_min_score_by_SD(lb));
}

static guint
_compute_size_shortened_by_ratio(struct grid_lb_s *lb)
{
	gdouble dl = lb->sorted_by_score->len;
	guint ul = ceil(dl * lb->shorten_ratio);
	return FUNC_CLAMP(ul, 1, lb->sorted_by_score->len);
}

static guint
_compute_shortened_size(struct grid_lb_s *lb)
{
	if (!lb->sorted_by_score->len)
		return 0;
	guint size_max_by_SD = _compute_size_shortened_by_SD(lb);
	guint size_max_by_ratio = _compute_size_shortened_by_ratio(lb);
	return MACRO_MIN(size_max_by_SD, size_max_by_ratio);
}

static void
_lb_reload(struct grid_lb_s *lb, service_provider_f provide)
{
	_lb_consume_provider(lb, provide);
	_lb_relink_services(lb);
	_lb_cumulate_scores_sum(lb);
	lb->size_max = _compute_shortened_size(lb);
	++ lb->version;
}

void
grid_lb_reload(struct grid_lb_s *lb, service_provider_f provide)
{
	if (!lb)
		return;

	grid_lb_lock(lb);
	_lb_flush(lb);
	_lb_reload(lb, provide);
	grid_lb_unlock(lb);

	GRID_DEBUG("LB [%s|%s] reloaded with [%u/%u] services",
			lb->ns, lb->srvtype, lb->sorted_by_score->len, lb->size_max);
}

static inline struct service_info_s*
_get_service_from_addr(struct grid_lb_s *lb, const struct addr_info_s *ai)
{
	gint idx = _get_index_by_addr(lb, ai);
	if (idx < 0)
		return NULL;

	struct service_info_s *si = lb->gpa->pdata[idx];
	if (!si)
		return NULL;
	return service_info_dup(si);
}

struct service_info_s*
grid_lb_get_service_from_addr(struct grid_lb_s *lb, const struct addr_info_s *ai)
{
	g_assert(ai != NULL);

	if (!lb)
		return NULL;

	grid_lb_lock(lb);
	struct service_info_s *si = _get_service_from_addr(lb, ai);
	grid_lb_unlock(lb);
	return si;
}

struct service_info_s*
grid_lb_get_service_from_url(struct grid_lb_s *lb, const gchar *url)
{
	addr_info_t ai;

	if (!lb || !url)
		return NULL;

	memset(&ai, 0, sizeof(struct addr_info_s));
	if (!grid_string_to_addrinfo(url, NULL, &ai))
		return NULL;

	return grid_lb_get_service_from_addr(lb, &ai);
}

static inline gboolean
_lb_is_addr_available(struct grid_lb_s *lb, const struct addr_info_s *ai)
{
	gint idx = _get_index_by_addr(lb, ai);
	if (idx < 0)
		return FALSE;

	struct service_info_s *si = lb->gpa->pdata[idx];
	if (!si)
		return FALSE;
	return si->score.value > 0;
}

gboolean
grid_lb_is_addr_available(struct grid_lb_s *lb, const struct addr_info_s *ai)
{
	g_assert(lb != NULL);
	g_assert(ai != NULL);

	grid_lb_lock(lb);
	gboolean rc = _lb_is_addr_available(lb, ai);
	grid_lb_unlock(lb);
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
	if (!lb)
		return 0;

	grid_lb_lock(lb);
	gsize rc = (gsize) lb->size_max;
	grid_lb_unlock(lb);

	return rc;
}

gsize
grid_lb_count_all(struct grid_lb_s *lb)
{
	if (!lb)
		return 0;

	grid_lb_lock(lb);
	gsize rc = (gsize) lb->gpa->len;
	grid_lb_unlock(lb);

	return rc;
}


/* Pool iterator constructors */

struct grid_lb_iterator_s*
grid_lb_iterator_share(struct grid_lb_iterator_s *sub)
{
	struct grid_lb_iterator_s *iter;

	g_assert(sub != NULL);

	iter = g_malloc0(sizeof(struct grid_lb_iterator_s));
	iter->lb = sub->lb;
	iter->version = sub->version;
	iter->type = LBIT_SHARED;
	iter->internals.shared.sub = sub;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_single_run(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(struct grid_lb_iterator_s));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_SINGLE;
	iter->internals.single.next_idx = 0;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_round_robin(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(struct grid_lb_iterator_s));
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

	iter = g_malloc0(sizeof(struct grid_lb_iterator_s));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_WRR;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_random(struct grid_lb_s *lb)
{
	struct grid_lb_iterator_s *iter;

	g_assert(lb != NULL);

	iter = g_malloc0(sizeof(struct grid_lb_iterator_s));
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

	iter = g_malloc0(sizeof(struct grid_lb_iterator_s));
	iter->lb = lb;
	iter->version = lb->version;
	iter->type = LBIT_WRAND;
	return iter;
}

struct grid_lb_iterator_s*
grid_lb_iterator_init(struct grid_lb_s *lb, const gchar *type)
{
	if (type && *type) {
		if (IS("RR"))
			return grid_lb_iterator_round_robin(lb);
		if (IS("RAND"))
			return grid_lb_iterator_random(lb);
		if (IS("WRR") || IS("SRR"))
			return grid_lb_iterator_weighted_round_robin(lb);
		if (IS("WRAND") || IS("SRAND"))
			return grid_lb_iterator_weighted_random(lb);
		if (IS("SINGLE"))
			return grid_lb_iterator_single_run(lb);
	}
	return grid_lb_iterator_round_robin(lb);
}

void
grid_lb_iterator_clean(struct grid_lb_iterator_s *iter)
{
	if (!iter)
		return;
	memset(iter, 0, sizeof(struct grid_lb_iterator_s));
	g_free(iter);
}

gboolean
grid_lb_iterator_is_srv_available(struct grid_lb_iterator_s *iter,
		const struct service_info_s *si)
{
	g_assert(iter != NULL);
	return grid_lb_is_srv_available(iter->lb, si);
}

gboolean
grid_lb_iterator_is_addr_available(struct grid_lb_iterator_s *iter,
		const struct addr_info_s *ai)
{
	g_assert(iter != NULL);
	return grid_lb_is_addr_available(iter->lb, ai);
}

static void
grid_lb_configure_kv(struct grid_lb_s *lb, const gchar *k, const gchar *v)
{
	if (!g_ascii_strcasecmp(k, "shorten_ratio")) {
		gdouble sr = g_ascii_strtod(v, NULL);
		sr = CLAMP(sr, 0.001, 1.001);
		grid_lb_lock(lb);
		lb->shorten_ratio = sr;
		grid_lb_unlock(lb);
		return;
	}

	if (!g_ascii_strcasecmp(k, "standard_deviation")) {
		grid_lb_lock(lb);
		lb->standard_deviation = metautils_cfg_get_bool(v, FALSE);
		grid_lb_unlock(lb);
		return;
	}

	if (!g_ascii_strcasecmp(k, "reset_delay")) {
		grid_lb_lock(lb);
		lb->reset_delay = g_ascii_strtoll(v, NULL, 10);
		grid_lb_unlock(lb);
		return;
	}
}

static void
grid_lb_configure_pair(struct grid_lb_s *lb, const gchar *k, gsize l)
{
	gchar *eq, *pair;

	pair = g_alloca(l+1);
	memcpy(pair, k, l+1);

	eq = strchr(pair, '=');
	if (!eq)
		grid_lb_configure_kv(lb, pair, "");
	else {
		*(eq++) = '\0';
		grid_lb_configure_kv(lb, pair, eq);
	}
}

static const gchar *
_next(const gchar *p, const gchar *sep)
{
	g_assert(p != NULL);
	g_assert(sep != NULL);
	for (; *p ; p++) {
		if (strchr(sep, *p))
			return p + 1;
	}
	return NULL;
}

void
grid_lb_configure_options(struct grid_lb_s *lb, const gchar *opts)
{

	int l;
	const gchar *p, *e;

	// Reset the defaults
	lb->shorten_ratio = 1.001;
	lb->standard_deviation = FALSE;

	// Set new specific options
	for (p=opts; p && *p ;p+=l) {
		l = !(e = _next(p, "?&")) ? (int)strlen(p) : (e - p);
		grid_lb_configure_pair(lb, p, l);
	}
}

void
grid_lb_iterator_configure(struct grid_lb_iterator_s *iter, const gchar *val)
{
	if (iter->type == LBIT_SHARED) {
		return;
	}

	switch (*val) {
		case 'R':
			if (g_str_has_prefix(val, "RR")) {
				if (iter->type != LBIT_RR) {
					iter->type = LBIT_RR;
					iter->internals.rr.next_idx = 0;
					iter->internals.rr.next_idx_global = 0;
				}
			}
			else if (g_str_has_prefix(val, "RAND")) {
				iter->type = LBIT_RAND;
			}

			grid_lb_configure_options(iter->lb, _next(val, "?&"));
			break;

		case 'S':
		case 'W':
			if (g_str_has_prefix(val, "WRR") || g_str_has_prefix(val, "SRR")) {
				if (iter->type != LBIT_WRR) {
					iter->type = LBIT_WRR;
					iter->internals.srr.next_idx = 0;
					iter->internals.srr.next_idx_global = 0;
					iter->internals.srr.current = 0;
					iter->internals.srr.last_reset = time(NULL);
				}
			}
			else if (g_str_has_prefix(val, "WRAND") || g_str_has_prefix(val, "SRAND")) {
				iter->type = LBIT_WRAND;
			}

			grid_lb_configure_options(iter->lb, _next(val, "?&"));
			break;
	}
}



/* Pool iterators runner */

/**
 * Ensure to get a value from the array.
 *
 * @param lb
 * @param idx
 * @return
 */

static inline gboolean
_result(struct service_info_s **pi, struct service_info_s *si)
{
	if (!si) {
		*pi = NULL;
		return FALSE;
	}

	*pi = si;
	return TRUE;
}

static inline gboolean
__next_SINGLE(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter,
		struct service_info_s **si)
{
	guint max;
	struct service_info_s *result = NULL;

	grid_lb_lock(lb);
	max = lb->gpa->len;
	if (iter->version == lb->version && max > 0) {
		if (iter->internals.single.next_idx < max)
			result = _get_raw(lb, iter->internals.single.next_idx ++);
	}
	grid_lb_unlock(lb);

	return _result(si, result);
}

static inline gboolean
__next_RR(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter,
		struct service_info_s **si, gboolean shorten)
{
	struct service_info_s *result = NULL;

	grid_lb_lock(lb);
	if (shorten) {
		result = _get_by_score(lb, iter->internals.rr.next_idx ++);
	} else if (lb->size_max > 0) {
		// This may be called on an iterator of type SRR,
		// in which "next_idx_global" field is at the same offset,
		// so it will work fine.
		result = _get_by_score_no_shorten(lb,
				iter->internals.rr.next_idx_global++);
	}
	grid_lb_unlock(lb);

	return _result(si, result);
}

static inline gboolean
__next_SRR(struct grid_lb_s *lb, struct grid_lb_iterator_s *iter,
		struct service_info_s **si)
{
	struct score_slot_s *slot;
	struct service_info_s *result = NULL;

	inline void reset(void) {
		GRID_DEBUG("SRR reset caused by: %s",
				iter->internals.srr.current > 0? "reset_delay" : "end of list");
		iter->internals.srr.next_idx = 0;
		slot = &g_array_index(lb->sorted_by_score, struct score_slot_s, 0);
		iter->internals.srr.current = slot->score;
		iter->internals.srr.last_reset = time(NULL);
	}
	inline void decrement(void) {
		iter->internals.srr.next_idx = 0;
		if (! --iter->internals.srr.current)
			reset();
	}

	grid_lb_lock(lb);
	if (lb->gpa->len > 0) {
		gint expiration = iter->internals.srr.last_reset + lb->reset_delay;
		// maybe rotate
		if (iter->internals.srr.current == 0 ||
				(lb->reset_delay > 0 && expiration < time(NULL)))
			reset();
		else if (iter->internals.srr.next_idx >= lb->sorted_by_score->len)
			decrement();
		else {
			slot = &g_array_index(lb->sorted_by_score, struct score_slot_s,
					iter->internals.srr.next_idx);
			if (iter->internals.srr.current > slot->score)
				decrement();
		}

		result = _get_by_score(lb, iter->internals.srr.next_idx ++);
	}
	grid_lb_unlock(lb);

	return _result(si, result);
}

static inline gboolean
__next_RAND(struct grid_lb_s *lb, struct service_info_s **si)
{
	struct service_info_s *result = NULL;
	register guint idx = rand();

	grid_lb_lock(lb);
	result = _get_by_score(lb, idx);
	grid_lb_unlock(lb);

	return _result(si, result);
}

static inline gboolean
__next_SRAND(struct grid_lb_s *lb, struct service_info_s **si)
{
	GArray *ga = NULL;
	guint32 needle;

	guint dichotomic_search(guint start, guint end) {
		inline guint32 guint32_absdiff(guint32 i0, guint32 i1) {
			return (i0 > i1) ? (i0 - i1) : (i1 - i0);
		}
		guint middle = (start + end) / 2;
		guint32 middle_sum = g_array_index(ga, struct score_slot_s, middle).sum;

		if ((end - start) <= 1) {
			guint32 diff_start, diff_end;
			diff_start = guint32_absdiff(middle_sum,
					g_array_index(ga, struct score_slot_s, start).sum);
			diff_end = guint32_absdiff(middle_sum,
					g_array_index(ga, struct score_slot_s, end).sum);
			return (diff_start < diff_end) ? start : end;
		}
		if (needle <= middle_sum)
			return dichotomic_search(middle, end);
		return dichotomic_search(start, middle);
	}

	struct service_info_s *result = NULL;
	needle = rand();

	grid_lb_lock(lb);
	if (lb->gpa->len > 0) {
		if (lb->sum_scored) {
			needle = needle % lb->sum_scored;
			ga = lb->sorted_by_score;
			result = _get_by_score(lb, dichotomic_search(0, ga->len));
		}
	}
	grid_lb_unlock(lb);

	return _result(si, result);
}

static inline gboolean
__next_SHARED(struct grid_lb_iterator_s *iter, struct service_info_s **si,
		gboolean shorten)
{
	if (!iter || !si)
		return FALSE;
	return grid_lb_iterator_next_shorten(iter->internals.shared.sub,
			si, shorten);
}

static gboolean
_iterator_next_shorten(struct grid_lb_iterator_s *iter,
		struct service_info_s **si, gboolean shorten)
{
	switch (iter->type) {
		case LBIT_SINGLE:
			return __next_SINGLE(iter->lb, iter, si);
		case LBIT_RR:
			return __next_RR(iter->lb, iter, si, shorten);
		case LBIT_WRR:
			if (shorten) {
				return __next_SRR(iter->lb, iter, si);
			} else {
				// We are asked to bypass shorten ratio, because no service
				// matching our criteria has been found. We have to iterate
				// over the whole list, so use RR.
				GRID_DEBUG("Fallback to RR without shorten ratio");
				return __next_RR(iter->lb, iter, si, FALSE);
			}
		case LBIT_RAND:
			return __next_RAND(iter->lb, si);
		case LBIT_WRAND:
			return __next_SRAND(iter->lb, si);
		case LBIT_SHARED:
			return __next_SHARED(iter, si, shorten);
	}

	g_assert_not_reached();
	return FALSE;
}

gboolean
grid_lb_iterator_next_shorten(struct grid_lb_iterator_s *iter,
		struct service_info_s **si, gboolean shorten)
{
	struct grid_lb_s *lb;

	if (!iter || !si)
		return FALSE;

	lb = iter->lb;
	g_assert(lb != NULL);

	if (lb->use_hook)
		lb->use_hook();

	return _iterator_next_shorten(iter, si, shorten);
}

gboolean
grid_lb_iterator_next(struct grid_lb_iterator_s *iter,
		struct service_info_s **si)
{
	return grid_lb_iterator_next_shorten(iter, si, TRUE);
}

static gsize
_get_iteration_limit(struct grid_lb_iterator_s *it, gboolean shorten)
{
	enum glbi_type_e type = _get_effective_type(it);

	if (type == LBIT_SINGLE || type == LBIT_RR)
		return shorten ? grid_lb_count(it->lb) : grid_lb_count_all(it->lb);
	return grid_lb_count_all(it->lb);
}

static gboolean
_distance_fits(guint reqdist, GTree *set, struct service_info_s *si)
{
	guint mindist = G_MAXUINT;
	gboolean runner(gpointer k, gpointer v, gpointer u) {
		(void) k;
		register guint d = distance_between_location(u,
				service_info_get_rawx_location(v, NULL));
		if (mindist > d)
			mindist = d;
		return mindist < reqdist;
	}

	if (!reqdist)
		return TRUE;

	const gchar *loc0 = service_info_get_rawx_location(si, NULL);
	if (NULL != loc0)
		g_tree_foreach(set, runner, (gpointer)loc0);
	return mindist >= reqdist;
}

static inline gboolean
_filter_matches(struct lb_next_opt_filter_s *f, struct service_info_s *si)
{
	return !f->hook || f->hook(si, f->data);
}

/**
 * Search for rawx servers that match storage class and distance requirements.
 *
 * @param max_server Number of servers to search for
 * @param req_dist Minimum distance between servers
 * @param stgclass The storage class that we want
 * @param iter An iterator over rawx services
 * @param location_blacklist Rawx locations (const gchar*) that we don't want,
 *   and that will be checked for minimum distance.
 * @param polled (out) Tree where to store the new rawx found (struct service_info_s)
 */
static void
_search_servers(struct grid_lb_iterator_s *iter, struct lb_next_opt_s *opt,
		const gchar *stgclass, GTree *polled, gboolean shorten)
{
	gsize limit = _get_iteration_limit(iter, shorten);

	if (GRID_DEBUG_ENABLED()) {
		GRID_DEBUG("SEARCH max=%u/%u dup=%d dist=%d stgclass=%s pool=%u"
				" shorten=%f filter=%p",
				(guint)g_tree_nnodes(polled), opt->req.max,
				opt->req.duplicates, opt->req.distance,
				stgclass, (guint)limit, iter->lb->shorten_ratio, opt->filter.hook);
	}

	while (limit > 0 && opt->req.max > (guint)g_tree_nnodes(polled)) {

		struct service_info_s *si = NULL;
		if (!_iterator_next_shorten(iter, &si, shorten))
			return;

		if (!service_info_check_storage_class(si, stgclass)
				|| !_filter_matches(&(opt->filter), si)
				|| !_distance_fits(opt->req.distance, polled, si))
		{
			service_info_clean(si);
			--limit;
		}
		else {
			struct service_info_s *old = g_tree_lookup(polled, &(si->addr));
			if (NULL == old) {
				// Ok, store the service
				g_tree_replace(polled, &(si->addr), si);
			}
			else {
				service_info_swap(si, old);
				service_info_clean(si);
				--limit;
			}
		}
	}
}

static gboolean
run_clean(gpointer k, gpointer v, gpointer u)
{
	(void) k, (void) u;
	service_info_clean(v);
	return FALSE;
}

static gint
cmp_addr(gconstpointer a, gconstpointer b, gpointer user_data)
{
	(void) user_data;
	return addr_info_compare(a, b);
}

static gint
cmp_ptr(gconstpointer a, gconstpointer b, gpointer user_data)
{
	(void) user_data;
	return CMP(a,b);
}

/* First search for servers matching the exact criterions.
 * If not enough services are found, bypass the shorten ratio
 * If still not enough servers are collected, retry with each fallback
 * storage classes. */
static void
_next_set(struct grid_lb_iterator_s *it, struct lb_next_opt_s *opt,
		const gchar *stgclass, GTree *polled, GSList *fallbacks)
{
	_search_servers(it, opt, stgclass, polled, TRUE);

	// TODO: possible optimization: in case of failure, reset next_idx
	// to same position as before our research (we won't use the
	// polled services, so pointer should not move).

	if (opt->req.max > (guint)g_tree_nnodes(polled)) {
		GRID_DEBUG("Shorten ratio bypass");
		_search_servers(it, opt, stgclass, polled, FALSE);
	}

	while (opt->req.max > (guint)g_tree_nnodes(polled) && fallbacks) {
		GRID_DEBUG("Fallback STGPOL");
		if (NULL != fallbacks->data)
			_search_servers(it, opt, fallbacks->data, polled, FALSE);
		fallbacks = fallbacks->next;
	}
}

gboolean
grid_lb_iterator_next_set(struct grid_lb_iterator_s *iter,
		struct service_info_s ***result, struct lb_next_opt_s *opt)
{
	// Sanity checks
	if (!iter || !iter->lb || !result || !opt || !opt->req.max)
		return FALSE;
	if (!opt->req.duplicates && opt->req.max > grid_lb_count_all(iter->lb))
		return FALSE;
	if (iter->lb->use_hook)
		iter->lb->use_hook();

	// Manage the duplication cases with a well chosen set
	GTree *polled = NULL;
	if (!opt->req.duplicates)
		polled = g_tree_new_full(cmp_addr, NULL, NULL, NULL);
	else
		polled = g_tree_new_full(cmp_ptr, NULL, NULL, NULL);

	const gchar *stgclass_name = storage_class_get_name(opt->req.stgclass);
	GSList *fallbacks = NULL;
	if (!opt->req.strict_stgclass)
		fallbacks = (GSList *)storage_class_get_fallbacks(opt->req.stgclass);

	// In a critical section to prevent several threads to iterate with
	// the sameiterator and then skip services...
	grid_lb_lock(iter->lb);
	_next_set(iter, opt, stgclass_name, polled, fallbacks);
	grid_lb_unlock(iter->lb);

	// Not enough servers found, fail
	if (opt->req.max > (guint)g_tree_nnodes(polled)) {
		g_tree_foreach(polled, run_clean, NULL);
		g_tree_destroy(polled);
		return FALSE;
	}

	*result = (struct service_info_s**) metautils_gpa_to_array(
			metautils_gtree_to_gpa(polled, TRUE), TRUE);
	return TRUE;
}

static gboolean
_ext_opt_filter(struct service_info_s *si, struct lb_next_opt_ext_s *opt_ext)
{
	GSList *l;
	struct service_info_s *si0;
	g_assert(opt_ext != NULL);

	// Check if the service is not forbidden
	for (l = opt_ext->srv_forbidden; l ;l=l->next) {
		if (!(si0 = l->data))
			continue;
		if (addr_info_equal(&si->addr, &si0->addr))
			return FALSE;
	}

	// Check if the service has already be choosen
	if (!opt_ext->req.duplicates) {
		for (l = opt_ext->srv_inplace; l ;l=l->next) {
			if (!(si0 = l->data))
				continue;
			if (addr_info_equal(&si->addr, &si0->addr))
				return FALSE;
		}
	}

	// Check if the distance fits fits already choose services
	for (l = opt_ext->srv_inplace; l ;l=l->next) {
		if (!(si0 = l->data))
			continue;
		guint d = distance_between_services(si, si0);
		if (opt_ext->req.distance > d)
			return FALSE;
	}

	// Now the custom filter, if any
	return _filter_matches(&(opt_ext->filter), si);
}

gboolean
grid_lb_iterator_next_set2(struct grid_lb_iterator_s *iter,
		struct service_info_s ***result, struct lb_next_opt_ext_s *opt_ext)
{
	struct lb_next_opt_s opt;

	memset(&opt, 0, sizeof(opt));
	memcpy(&(opt.req), &(opt_ext->req), sizeof(struct lb_next_opt_simple_s));

	opt.filter.hook = (service_filter) _ext_opt_filter;
	opt.filter.data = opt_ext;
	return grid_lb_iterator_next_set(iter, result, &opt);
}

/* ------------------------------------------------------------------------- */

struct grid_lbpool_s*
grid_lbpool_create(const gchar *ns)
{
	g_assert(ns != NULL);

	struct grid_lbpool_s *glp = g_malloc0(sizeof(struct grid_lbpool_s));

	g_static_rw_lock_init(&(glp->rwlock));

	metautils_strlcpy_physical_ns(glp->ns, ns, sizeof(glp->ns));

	glp->pools = g_tree_new_full(metautils_strcmp3, NULL, g_free,
			(GDestroyNotify)grid_lb_clean);
	glp->iterators = g_tree_new_full(metautils_strcmp3, NULL,
			g_free, (GDestroyNotify)grid_lb_iterator_clean);
	return glp;
}

void
grid_lbpool_destroy(struct grid_lbpool_s *glp)
{
	if (!glp)
		return;

	g_static_rw_lock_writer_lock(&(glp->rwlock));

	if (glp->iterators)
		g_tree_destroy(glp->iterators);
	if (glp->pools)
		g_tree_destroy(glp->pools);

	g_static_rw_lock_writer_unlock(&(glp->rwlock));
	g_static_rw_lock_free(&(glp->rwlock));

	memset(glp, 0, sizeof(struct grid_lbpool_s));
	g_free(glp);
}

static void
_ensure(struct grid_lbpool_s *glp, const gchar *srvtype,
		struct grid_lb_s **plb, struct grid_lb_iterator_s **pit)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iterator;

	if (!(lb = g_tree_lookup(glp->pools, srvtype))) {
		lb = grid_lb_init(glp->ns, srvtype);
		g_tree_insert(glp->pools, g_strdup(srvtype), lb);
	}

	if (!(iterator = g_tree_lookup(glp->iterators, srvtype))) {
		iterator = grid_lb_iterator_round_robin(lb);
		g_tree_insert(glp->iterators, g_strdup(srvtype), iterator);
	}

	if (pit)
		*pit = iterator;
	if (plb)
		*plb = lb;
}

void
grid_lbpool_configure_string(struct grid_lbpool_s *glp, const gchar *srvtype,
		const gchar *cfg)
{
	g_assert(glp != NULL);
	g_assert(srvtype != NULL);
	g_assert(cfg != NULL);
	grid_lb_iterator_configure (grid_lbpool_ensure_iterator(glp, srvtype), cfg);
}

static void
_configure_string(struct grid_lbpool_s *glp, const gchar *kv)
{
	GRID_TRACE("parsing : [%s]", kv);
	const gchar *val = strchr(kv, '=');

	if (!val || kv == val) {
		GRID_DEBUG("Invalid format");
		return;
	}

	gsize len = val - kv + 1;
	gchar srvtype[len];
	memcpy(srvtype, kv, val - kv);
	srvtype[ len-1 ] = 0;
	++ val;

	grid_lbpool_configure_string(glp, srvtype, val);
}


void
grid_lbpool_reconfigure(struct grid_lbpool_s *glp,
		struct namespace_info_s *ni)
{
	if (!glp || !ni || !ni->options) {
		GRID_DEBUG("Invalid parameter (%s)", __FUNCTION__);
		return ;
	}

	GHashTableIter iter;
	gpointer k, v;
	g_hash_table_iter_init(&iter, ni->options);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		if (!g_str_has_prefix((gchar*)k, "lb."))
			continue;
		GString *str = g_string_new((gchar*)k + (sizeof("lb.") -1));
		str = g_string_append_len(g_string_append(str, "="),
				((char *)((GByteArray*)v)->data), ((GByteArray*)v)->len);
		_configure_string(glp, str->str);
		g_string_free(str, TRUE);
	}
}

struct grid_lb_s *
grid_lbpool_get_lb (struct grid_lbpool_s *glp, const gchar *srvtype)
{
	g_assert (glp != NULL);
	g_assert (srvtype != NULL);

	g_static_rw_lock_reader_lock(&(glp->rwlock));
	struct grid_lb_s *lb = g_tree_lookup(glp->pools, srvtype);
	g_static_rw_lock_reader_unlock(&(glp->rwlock));

	return lb;
}

struct grid_lb_iterator_s *
grid_lbpool_ensure_iterator (struct grid_lbpool_s *glp, const gchar *srvtype)
{
	struct grid_lb_iterator_s *iterator =  NULL;
	g_assert (glp != NULL);
	g_assert (srvtype != NULL);

	g_static_rw_lock_writer_lock(&(glp->rwlock));
	_ensure (glp, srvtype, NULL, &iterator);
	g_static_rw_lock_writer_unlock(&(glp->rwlock));

	return iterator;
}

struct grid_lb_s *
grid_lbpool_ensure_lb (struct grid_lbpool_s *glp, const gchar *srvtype)
{
	struct grid_lb_s *lb =  NULL;
	g_assert (glp != NULL);
	g_assert (srvtype != NULL);

	g_static_rw_lock_writer_lock(&(glp->rwlock));
	_ensure (glp, srvtype, &lb, NULL);
	g_static_rw_lock_writer_unlock(&(glp->rwlock));

	return lb;
}

void
grid_lbpool_reload(struct grid_lbpool_s *glp, const gchar *srvtype,
		service_provider_f provider)
{
	g_assert(glp != NULL);
	g_assert(srvtype != NULL);
	g_assert(provider != NULL);
	return grid_lb_reload(grid_lbpool_ensure_lb(glp, srvtype), provider);
}

GError*
grid_lbpool_reload_json(struct grid_lbpool_s *glp, const gchar *srvtype,
		const gchar *encoded)
{
	g_assert(glp != NULL);
	g_assert(srvtype != NULL);
	return grid_lb_reload_json(grid_lbpool_ensure_lb(glp, srvtype), encoded);
}

GError*
grid_lbpool_reload_json_object(struct grid_lbpool_s *glp, const gchar *srvtype,
		struct json_object *obj)
{
	g_assert(glp != NULL);
	g_assert(srvtype != NULL);
	return grid_lb_reload_json_object(grid_lbpool_ensure_lb(glp, srvtype), obj);
}

struct grid_lb_iterator_s*
grid_lbpool_get_iterator(struct grid_lbpool_s *glp, const gchar *srvtype)
{
	g_assert(glp != NULL);
	g_assert(srvtype != NULL);

	g_static_rw_lock_reader_lock(&(glp->rwlock));
	struct grid_lb_iterator_s *iter = g_tree_lookup(glp->iterators, srvtype);
	g_static_rw_lock_reader_unlock(&(glp->rwlock));

	return iter;
}

const gchar*
grid_lbpool_namespace(struct grid_lbpool_s *glp)
{
	g_assert(glp != NULL);
	return glp->ns;
}

struct service_info_s*
grid_lbpool_get_service_from_url(struct grid_lbpool_s *glp,
		const gchar *srvtype, const gchar *url)
{
	g_assert(glp != NULL);
	g_assert(srvtype != NULL);
	g_assert(url != NULL);

	return grid_lb_get_service_from_url(grid_lbpool_get_lb(glp, srvtype), url);
}

GError *
grid_lb_reload_json_object(struct grid_lb_s *lb, struct json_object *obj)
{
	if (!lb)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid parameter");
	if (!json_object_is_type(obj, json_type_array))
		return NEWERROR(CODE_BAD_REQUEST, "JSON object is not an array");

	int i = json_object_array_length(obj);
	gboolean provide(struct service_info_s **p_si) {
		*p_si = NULL;
		while (i > 0) {
			--i;
			struct json_object *item = json_object_array_get_idx(obj, i);
			if (!item || !json_object_is_type(item, json_type_object))
				return TRUE;
			*p_si = NULL;
			GError *e = service_info_load_json_object(item, p_si);
			if (!e)
				return FALSE;
			g_clear_error(&e);
		}
		*p_si = NULL;
		return TRUE;
	}
	grid_lb_reload(lb, provide);
	return NULL;
}

GError *
grid_lb_reload_json(struct grid_lb_s *lb, const gchar *encoded)
{
	struct json_tokener *tok = json_tokener_new();
	struct json_object *obj = json_tokener_parse_ex(tok,
			encoded, strlen(encoded));
	json_tokener_free(tok);
	GError *err = grid_lb_reload_json_object(lb, obj);
	json_object_put(obj);
	return err;
}

