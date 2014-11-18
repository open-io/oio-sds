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

enum {
	/*! If set, when there is no activity, the untouched slots are filled
	 * with zeros. If not set (default), the previous value is repeated. */
	RRD_FLAG_SHIFT_SET = 0x01,
};

struct grid_single_rrd_s
{
	time_t last;
	time_t period;
	guint32 flags;
	guint64 def;
	guint64 l0[];
};

struct grid_single_rrd_s*
grid_single_rrd_create(time_t now, time_t period)
{
	struct grid_single_rrd_s *gsr;

	EXTRA_ASSERT(period > 1);

	gsr = g_malloc0(sizeof(struct grid_single_rrd_s)
			+ (period * sizeof(guint64)));
	gsr->last = now;
	gsr->period = period;

	return gsr;
}

void
grid_single_rrd_destroy(struct grid_single_rrd_s *gsr)
{
	if (gsr)
		g_free(gsr);
}

void
grid_single_rrd_set_default(struct grid_single_rrd_s *gsr, guint64 v)
{
	gsr->def = v;
	gsr->flags |= RRD_FLAG_SHIFT_SET;
}

static inline void
_rrd_set(struct grid_single_rrd_s *gsr, guint64 v)
{
	gsr->l0[gsr->last % gsr->period] = v;
}

static inline guint64
_rrd_get(struct grid_single_rrd_s *gsr, time_t at)
{
	return gsr->l0[at % gsr->period];
}

static inline guint64
_rrd_current(struct grid_single_rrd_s *gsr)
{
	return _rrd_get(gsr, gsr->last);
}

static guint64
_rrd_past(struct grid_single_rrd_s *gsr, time_t period)
{
	return _rrd_get(gsr, gsr->last - period);
}

static void
_gsr_manage_timeshift(struct grid_single_rrd_s *gsr, time_t now)
{
	if (now == gsr->last)
		return ;

	guint64 v = (gsr->flags & RRD_FLAG_SHIFT_SET) ? gsr->def : _rrd_current(gsr);
	for (time_t i=0; gsr->last != now && i++ < gsr->period ;) {
		gsr->last ++;
		_rrd_set(gsr,v);
	}
	gsr->last = now;
}

void
grid_single_rrd_push(struct grid_single_rrd_s *gsr, time_t now, guint64 v)
{
	_gsr_manage_timeshift(gsr, now);
	_rrd_set(gsr, v);
}

void
grid_single_rrd_pushifmax(struct grid_single_rrd_s *gsr, time_t now, guint64 v)
{
	_gsr_manage_timeshift(gsr, now);
	guint64 v0 = _rrd_current(gsr);
	_rrd_set(gsr, MAX(v0,v));
}

guint64
grid_single_rrd_get(struct grid_single_rrd_s *gsr, time_t now)
{
	_gsr_manage_timeshift(gsr, now);
	return _rrd_current(gsr);
}

guint64
grid_single_rrd_get_delta(struct grid_single_rrd_s *gsr,
		time_t now, time_t period)
{
	EXTRA_ASSERT(period <= gsr->period);
	_gsr_manage_timeshift(gsr, now);
	return _rrd_current(gsr) - _rrd_past(gsr, period);
}

guint64
grid_single_rrd_get_max(struct grid_single_rrd_s *gsr,
		time_t now, time_t period)
{
	EXTRA_ASSERT(period <= gsr->period);
	_gsr_manage_timeshift(gsr, now);
	guint64 maximum = 0;
	for (time_t i=0; i<period ;i++) {
		guint64 m = _rrd_past(gsr,i);
		maximum = MAX(maximum,m);
	}
	return maximum;
}

void
grid_single_rrd_get_allmax(struct grid_single_rrd_s *gsr,
		time_t now, time_t period, guint64 *out)
{
	EXTRA_ASSERT(period <= gsr->period);
	_gsr_manage_timeshift(gsr, now);
	guint64 maximum = 0;
	for (time_t i=0; i<period ;i++) {
		guint64 m = _rrd_past(gsr,i);
		out[i] = maximum = MAX(maximum,m);
	}
}

void
grid_single_rrd_feed(struct grid_stats_holder_s *gsh, time_t now, ...)
{
	struct grid_single_rrd_s *gsr;
	gchar *n;
	va_list va;

	EXTRA_ASSERT(gsh != NULL);

	va_start(va, now);
	g_mutex_lock(gsh->lock);
	while (NULL != (n = va_arg(va, gchar*))) {
		gsr = va_arg(va, struct grid_single_rrd_s*);
		if (!gsr)
			break;
		_gsr_manage_timeshift(gsr, now);
		_rrd_set(gsr, _real_get(gsh->hashset, n));
	}
	g_mutex_unlock(gsh->lock);
	va_end(va);
}

