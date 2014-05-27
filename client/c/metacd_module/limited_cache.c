#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <metautils/lib/metautils.h>

#include "./limited_cache.h"

struct limited_cache_element_s
{
	gpointer k;
	gpointer v;
	time_t date_access;
	struct limited_cache_element_s *prev;
	struct limited_cache_element_s *next;
};


struct limited_cache_s
{
	time_t expiration;
	guint32 flags;
	gssize limit;
	gssize size;
	GDestroyNotify free_k;
	GDestroyNotify free_v;
	value_copier_f copy_k;
	value_copier_f copy_v;
	GHashTable *ht;
	struct limited_cache_element_s BEACON;
	GMutex *mutex;
};


limited_cache_t* limited_cache_create (gssize limit, time_t expiration,
	struct limited_cache_callbacks *callbacks, guint32 flags, GError **err)
{
	struct limited_cache_s *lc = NULL;
	GHashTable *ht=NULL;
	GMutex *mutex = NULL;
	
	mutex = g_mutex_new ();
	if (!mutex) {
		GSETERROR(err,"Mutex allocation failure");
		return NULL;
	}
	
	ht = g_hash_table_new_full (callbacks->hash_k, callbacks->equal_k, NULL, NULL);
	if (!ht) {
		g_mutex_free(mutex);
		GSETERROR(err,"Memory allocation failure");
		return NULL;
	}
	
	lc = g_try_malloc0(sizeof(struct limited_cache_s));
	if (!lc) {
		g_mutex_free(mutex);
		g_hash_table_destroy(ht);
		GSETERROR(err,"Memory allocation failure (size=%d) : %s",
			sizeof(struct limited_cache_s), strerror(errno));
		return NULL;
	}
	
	lc->flags = flags;
	lc->expiration = expiration;
	lc->limit = limit;
	lc->size = 0;
	lc->free_k = callbacks->free_k;
	lc->free_v = callbacks->free_v;
	lc->copy_k = callbacks->copy_k;
	lc->copy_v = callbacks->copy_v;
	lc->ht = ht;
	lc->BEACON.prev = &(lc->BEACON);
	lc->BEACON.next = &(lc->BEACON);
	lc->mutex = mutex;

	return lc;
}

static void
UNCHECKED_remove_element(limited_cache_t *lc, struct limited_cache_element_s *e)
{
	struct limited_cache_element_s *e_prev, *e_next;

	if (GRID_TRACE_ENABLED()) {
		// XXX: Remove this when cache is used for anything else than cid
		gchar str_cid[65];
		container_id_to_string(e->k, str_cid, 65);
		TRACE("cleaning entry %s -> %p", str_cid, e->v);
	}

	/*restore the chain*/
	e_prev = e->prev;
	e_next = e->next;
	e_next->prev = e_prev;
	e_prev->next = e_next;

	/* remove it from the hash table if it is the referenced element */
	if (e == g_hash_table_lookup(lc->ht, e->k))
		g_hash_table_remove(lc->ht, e->k);
	
	/*free the element*/
	if (lc->free_k)
		lc->free_k (e->k);
	if (lc->free_v)
		lc->free_v (e->v);
	g_free(e);

	/*decreases the size*/
	lc->size--;
}

static gboolean
UNCHECKED_pop_last (limited_cache_t *lc)
{
	struct limited_cache_element_s *e;

	e = lc->BEACON.prev;
	if (!e || (e==&(lc->BEACON)))
		return FALSE;
		
	UNCHECKED_remove_element(lc, e);
	return TRUE;
}

static gboolean
UNCHECKED_pop_if_older (limited_cache_t *lc, time_t needle)
{
	struct limited_cache_element_s *e;

	e = lc->BEACON.prev;
	if (!e || (e==&(lc->BEACON)))
		return FALSE;
	if (e->date_access >= needle)
		return FALSE;

	UNCHECKED_remove_element(lc, e);
	return TRUE;
}

static void
_lc_clean(limited_cache_t *lc, guint *count)
{
	guint c;
	time_t needle;
	if (!lc) {
		WARN ("Cannot clean %p", lc);
		return;
	}

	needle = (lc->expiration>0) ? (time(0) - lc->expiration) : 0;
	c = 0U;

	if (lc->limit > 0) {
		if (lc->limit < lc->size)
			DEBUG("cleaning %"G_GSSIZE_FORMAT" oldest entries of cache %p",
					lc->size - lc->limit, (void*)lc);
		while ((lc->size > lc->limit) && UNCHECKED_pop_last (lc))
			c++;
	}
	if (lc->expiration >= 0) {
		DEBUG("cleaning entries older than %lu from cache %p",
				needle, (void*)lc);
		while (UNCHECKED_pop_if_older(lc, needle))
			c++;
	}

	if (count)
		*count = c;
}


void limited_cache_destroy (limited_cache_t *lc)
{
	GMutex *mutex;
	if (!lc)
		return;
	mutex = lc->mutex;
	g_mutex_lock(mutex);
	while (UNCHECKED_pop_last (lc));
	g_hash_table_destroy (lc->ht);
	memset(lc, 0x00, sizeof(limited_cache_t));
	g_free (lc);
	g_mutex_unlock(mutex);
	g_mutex_free(mutex);
}

void limited_cache_clean (limited_cache_t *lc)
{
	guint count = 0;
	
	g_mutex_lock(lc->mutex);
	_lc_clean(lc, &count);
	g_mutex_unlock(lc->mutex);
	
	INFO("%u elements cleaned", count);
}


void
limited_cache_set_limit (limited_cache_t *lc, gssize s)
{
	if (!lc)
		return;

	g_mutex_lock(lc->mutex);
	lc->limit = (s>0?s:0);
	g_mutex_unlock(lc->mutex);
}

time_t
limited_cache_get_expiration (limited_cache_t *lc)
{
	time_t result;

	if (!lc)
		return -1;

	g_mutex_lock(lc->mutex);
	result = lc->expiration;
	g_mutex_unlock(lc->mutex);

	return result;
}

gssize
limited_cache_get_limit (limited_cache_t *lc)
{
	gssize result;

	if (!lc)
		return -1;

	g_mutex_lock(lc->mutex);
	result = lc->limit;
	g_mutex_unlock(lc->mutex);

	return result;
}

void limited_cache_put (limited_cache_t *lc, gpointer k, gpointer v)
{
	struct limited_cache_element_s *e = NULL, *e_old;
	
	if (!lc || !k) {
		ALERT("Invalid parameter");
		return ;
	}

	e = g_try_malloc0 (sizeof(struct limited_cache_element_s));
	if (!e) {
		ALERT("Memory allocation failure");
		return ;
	}

	e->k = lc->copy_k ? lc->copy_k(k) : k;
	e->v = lc->copy_v ? lc->copy_v(v) : v;
	if (!e->k) {
		if (e->v && lc->free_v)
			lc->free_v(e->v);
		if (e->k && lc->free_k)
			lc->free_k(e->k);
		g_free(e);
		return ;
	}

	g_mutex_lock (lc->mutex);	

	/*remove the old entry*/
	if (NULL != (e_old = g_hash_table_lookup(lc->ht, e->k))) {
		UNCHECKED_remove_element(lc, e_old);
	}
	
	/*insert in the hash table*/	
	g_hash_table_insert (lc->ht, e->k, e);

	/*bring in front of the list*/	
	lc->BEACON.next->prev = e;
	e->next = lc->BEACON.next;
	lc->BEACON.next = e;
	e->prev = &(lc->BEACON);

	/* touch the element */
	e->date_access = time(0);
	lc->size ++;
	_lc_clean(lc, NULL);
	g_mutex_unlock (lc->mutex);	
}

static
gpointer limited_cache_lookup(limited_cache_t *lc, gconstpointer k, gboolean *p_cache_has_key)
{
	time_t now;
	gpointer eData=NULL;
	struct limited_cache_element_s *e=NULL;
	
	if (!lc || !k) {
		WARN("Invalid parameter");
		return NULL;
	}

	now = time(0);

	g_mutex_lock(lc->mutex);
	if (p_cache_has_key) {
		*p_cache_has_key = g_hash_table_lookup_extended(lc->ht, k, NULL, (gpointer*) &e);
	} else {
		e = (struct limited_cache_element_s*) g_hash_table_lookup (lc->ht, k);
	}
	if (!e) {
		g_mutex_unlock(lc->mutex);	
		return NULL;
	}

	if (e->date_access < (now - lc->expiration)) { /* EXPIRED */
		UNCHECKED_remove_element(lc, e);
		g_mutex_unlock(lc->mutex);
		return NULL;
	}

	if (!(lc->flags & LCFLAG_NOATIME)) {
		/*remove from the list*/
		e->next->prev = e->prev;
		e->prev->next = e->next;
		e->prev = e->next = NULL;

		/*bring in front of the list*/
		lc->BEACON.next->prev = e;
		e->next = lc->BEACON.next;
		lc->BEACON.next = e;
		e->prev = &(lc->BEACON);
	
		/* touch the element */
		e->date_access = now;
	}

	eData = lc->copy_v ? lc->copy_v(e->v) : e->v;
	g_mutex_unlock(lc->mutex);

	return eData;
}

gboolean
limited_cache_has(limited_cache_t *lc, gconstpointer k, gpointer *p_val)
{
	gboolean has_val;
	gpointer valret = limited_cache_lookup(lc, k, &has_val);
	if (p_val)
		*p_val = valret;
	return has_val;
}

gpointer
limited_cache_get (limited_cache_t *lc, gconstpointer k)
{
	return limited_cache_lookup(lc, k, NULL);
}

void
limited_cache_del (limited_cache_t *lc, gconstpointer k)
{
	struct limited_cache_element_s *e=NULL;
	
	if (!lc || !k) {
		WARN("invalid parameter");
		return;
	}
	
	g_mutex_lock(lc->mutex);
	e = (struct limited_cache_element_s*) g_hash_table_lookup (lc->ht, k);
	if (e)
		UNCHECKED_remove_element(lc, e);
	g_mutex_unlock(lc->mutex);
}


void
limited_cache_flush(limited_cache_t *lc)
{
	guint count = 0;
	time_t real_expiration;
	
	if (!lc)
		return;

	g_mutex_lock(lc->mutex);
	real_expiration = lc->expiration;
	lc->expiration = 0;
	_lc_clean(lc, &count);
	lc->expiration = real_expiration;
	g_mutex_unlock(lc->mutex);
	
	INFO("Flush done : %u elements", count);
}

gssize
limited_cache_get_size (limited_cache_t *lc)
{
	gssize result;

	if (!lc)
		return -1;

	g_mutex_lock(lc->mutex);
	result = lc->size;
	g_mutex_unlock(lc->mutex);

	return result;
}

