#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.stats"
#endif

#include <stdarg.h>
#include <fnmatch.h>

#include <metautils/lib/metautils.h>

#include "internals.h"
#include "stats_holder.h"

struct grid_stats_holder_s
{
	GMutex *lock;
	GTree *hashset;
};

/* -------------------------------------------------------------------------- */

static inline gboolean
_gsh_check(struct grid_stats_holder_s *gsh)
{
	return gsh && gsh->hashset;
}

static inline void
_real_increment_h(GTree *hashset, hashstr_t *hn, guint64 v)
{
	gpointer old;

	if ((old = g_tree_lookup(hashset, hn)) != NULL) {
		*((guint64*)old) += v;
	}
	else {
		g_tree_replace(hashset, hashstr_dup(hn), g_memdup(&v, sizeof(v)));
	}
}

static void
_real_increment(GTree *hashset, const gchar *n, guint64 v)
{
	struct hashstr_s *hn;

	HASHSTR_ALLOCA(hn, n);
	_real_increment_h(hashset, hn, v);
}

static guint64
_real_get(GTree *hashset, const gchar *n)
{
	guint64 *p;
	struct hashstr_s *hn;

	HASHSTR_ALLOCA(hn, n);
	p = g_tree_lookup(hashset, hn);
	return p ? *p : 0LLU;
}

/* -------------------------------------------------------------------------- */

struct grid_stats_holder_s *
grid_stats_holder_init(void)
{
	struct grid_stats_holder_s *result = g_malloc0(sizeof(*result));
	result->lock = g_mutex_new();
	result->hashset = g_tree_new_full(
			hashstr_quick_cmpdata, NULL,
			g_free, g_free);
	return result;
}

void
grid_stats_holder_clean(struct grid_stats_holder_s *gsh)
{
	if (!gsh)
		return;

	if (gsh->lock) {
		GMutex *lock = gsh->lock;
		gsh->lock = NULL;
		g_mutex_lock(lock);
		g_mutex_unlock(lock);
		g_mutex_free(lock);
	}

	if (gsh->hashset) {
		g_tree_destroy(gsh->hashset);
		gsh->hashset = NULL;
	}

	g_free(gsh);
}

void
grid_stats_holder_set(struct grid_stats_holder_s *gsh, ...)
{
	gchar *n;
	guint64 v;
	va_list va;

	if (!_gsh_check(gsh))
		return;

	va_start(va, gsh);
	g_mutex_lock(gsh->lock);
	while ((n = va_arg(va, gchar*)) != NULL) {
		v = va_arg(va, guint64);
		g_tree_replace(gsh->hashset, hashstr_create(n),
				g_memdup(&v, sizeof(v)));
	}
	g_mutex_unlock(gsh->lock);
	va_end(va);
}

void
grid_stats_holder_increment(struct grid_stats_holder_s *gsh, ...)
{
	gchar *n;
	guint64 v;
	va_list va;

	if (!_gsh_check(gsh))
		return;

	va_start(va, gsh);
	while ((n = va_arg(va, gchar*)) != NULL) {
		v = va_arg(va, guint64);
		_real_increment(gsh->hashset, n, v);
	}
	va_end(va);
}

void
grid_stats_holder_get(struct grid_stats_holder_s *gsh, ...)
{
	gchar *n;
	guint64 *pv;
	va_list va;

	if (!_gsh_check(gsh))
		return;

	va_start(va, gsh);
	g_mutex_lock(gsh->lock);
	while ((n = va_arg(va, gchar*)) && (pv = va_arg(va, guint64*)))
		*pv = _real_get(gsh->hashset, n);
	g_mutex_unlock(gsh->lock);
	va_end(va);
}

void
grid_stats_holder_foreach(struct grid_stats_holder_s *gsh, const gchar *p,
	gboolean (*output)(const gchar *, guint64 value))
{
	gboolean traverser(gpointer k, gpointer pv, gpointer ignored) {
		(void) ignored;
		guint64 v = *((guint64*)pv);
		const gchar *n = hashstr_str((struct hashstr_s*)k);
		if (!p || !*p || 0 != fnmatch(p, n, FNM_NOESCAPE))
			output(n, v);
		return FALSE;
	}

	if (!_gsh_check(gsh) || !output)
		return;

	g_mutex_lock(gsh->lock);
	g_tree_foreach(gsh->hashset, traverser, NULL);
	g_mutex_unlock(gsh->lock);
}

void
grid_stats_holder_zero(struct grid_stats_holder_s *gsh)
{
	gboolean traverser(gpointer k, gpointer v, gpointer ignored) {
		(void) k;
		(void) ignored;
		*((guint64*)v) = 0;
		return FALSE;
	}

	if (!_gsh_check(gsh))
		return;
	g_tree_foreach(gsh->hashset, traverser, NULL);
}

void
grid_stats_holder_increment_merge(struct grid_stats_holder_s *base,
		struct grid_stats_holder_s *inc)
{
	gboolean traverser(gpointer k, gpointer pv, gpointer ignored) {
		guint64 v;
		(void) ignored;
		if (0 != (v = *((guint64*)pv)))
			_real_increment_h(base->hashset, (struct hashstr_s*)k, v);
		return FALSE;
	}

	if (!_gsh_check(base) || !_gsh_check(inc))
		return;

	g_mutex_lock(base->lock);
	g_tree_foreach(inc->hashset, traverser, NULL);
	g_mutex_unlock(base->lock);
}

/* ------------------------------------------------------------------------- */

struct grid_single_rrd_s
{
	time_t last;
	time_t period;
	guint64 l0[];
};

struct grid_single_rrd_s*
grid_single_rrd_create(time_t period)
{
	struct grid_single_rrd_s *result;

	EXTRA_ASSERT(period > 1);

	result = g_malloc0(sizeof(struct grid_single_rrd_s)
			+ (period * sizeof(guint64)));
	result->last = time(0);
	result->period = period;

	return result;
}

void
grid_single_rrd_destroy(struct grid_single_rrd_s *gsr)
{
	if (gsr)
		g_free(gsr);
}

static void
_gsr_blank_empty_slots(struct grid_single_rrd_s *gsr, guint64 v, time_t now)
{
	time_t i;

	for (i=gsr->last; i<now ;)
		gsr->l0[(i++) % gsr->period] = v;
	gsr->last = now;
}

void
grid_single_rrd_push(struct grid_single_rrd_s *gsr, guint64 v)
{
	time_t now;

	if ((now = time(0)) != gsr->last)
		_gsr_blank_empty_slots(gsr, gsr->l0[gsr->last % gsr->period], now);

	gsr->l0[now % gsr->period] = v;
	gsr->last = now;
}

guint64
grid_single_rrd_get(struct grid_single_rrd_s *gsr)
{
	time_t now;

	if ((now = time(0)) != gsr->last)
		_gsr_blank_empty_slots(gsr, gsr->l0[gsr->last % gsr->period], now);

	return gsr->l0[now % gsr->period];
}

guint64
grid_single_rrd_get_delta(struct grid_single_rrd_s *gsr, time_t period)
{
	time_t now;

	EXTRA_ASSERT(period < gsr->period);

	if ((now = time(0)) != gsr->last)
		_gsr_blank_empty_slots(gsr, gsr->l0[gsr->last % gsr->period], now);

	return gsr->l0[now % gsr->period] - gsr->l0[(now-period) % gsr->period];
}

void
grid_single_rrd_feed(struct grid_stats_holder_s *gsh, ...)
{
	struct grid_single_rrd_s *gsr;
	gchar *n;
	va_list va;
	time_t now;

	EXTRA_ASSERT(gsh != NULL);

	now = time(0);

	va_start(va, gsh);
	g_mutex_lock(gsh->lock);
	while (NULL != (n = va_arg(va, gchar*))) {
		gsr = va_arg(va, struct grid_single_rrd_s*);
		if (!gsr)
			break;
		if (now != gsr->last)
			_gsr_blank_empty_slots(gsr, gsr->l0[gsr->last % gsr->period], now);
		gsr->l0[now % gsr->period] = _real_get(gsh->hashset, n);
		gsr->last = now;
	}
	g_mutex_unlock(gsh->lock);
	va_end(va);
}

