#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include "./locktab.h"

#ifdef _USE_GLIB_THREADS
# define LOCK_CREATE(R) do { R = g_mutex_new(); } while (0)
# define LOCK_FREE(R) g_mutex_destroy(R);
# define COND_CREATE(R) do { R = g_cond_new(); } while (0)
# define COND_FREE(R) g_cond_destroy(R);
# define LOCKTAB_UNLOCK(LT) g_mutex_unlock(LT->mutex)
# define LOCKTAB_LOCK(LT) g_mutex_lock(LT->mutex)
# define LOCKELT_SIGNAL(LE) g_cond_signal(lE->cond)
# define LOCKELT_WAIT(LT,LE) g_cond_wait(lE->cond, LT->mutex)
typedef GCond sync_cond_t;
typedef GMutex sync_mutex_t;
#else
# define LOCK_CREATE(R) do {\
	R = g_try_malloc0(sizeof(sync_mutex_t));\
	pthread_mutex_init(R,NULL);\
} while (0)
# define LOCK_FREE(R) pthread_mutex_destroy(R)
# define COND_CREATE(R) do {\
	R = g_try_malloc0(sizeof(sync_cond_t));\
	pthread_cond_init(R, NULL);\
} while (0)
# define COND_FREE(R) do {\
	pthread_cond_destroy(R);\
	g_free(R);\
} while (0)
# define LOCKTAB_UNLOCK(LT) pthread_mutex_unlock(LT->mutex)
# define LOCKTAB_LOCK(LT) pthread_mutex_lock(LT->mutex)
# define LOCKELT_SIGNAL(LE) pthread_cond_signal(LE->cond)
# define LOCKELT_WAIT(LT,LE) pthread_cond_wait(LE->cond,LT->mutex)
typedef pthread_cond_t sync_cond_t;
typedef pthread_mutex_t sync_mutex_t;
#endif

struct lockelement_s {
	gpointer key;
	gpointer udata;
	guint32 ref_count;
	/* DO NOT FREE */
	GThread *owner;
	sync_cond_t *cond;
	/* the following fields build the ring */
	struct lockelement_s *next;
	struct lockelement_s *prev;
};

struct locktab_s {
	gboolean checks_allowed;
	sync_mutex_t *mutex;
	sync_cond_t **cond_array;
	gsize cond_size;
	struct locktab_ctx_s ctx;
	/*locked elements storage*/
	GHashTable *ht;
	struct lockelement_s RING;
};

gsize
locktab_get_struct_size(void)
{
	return sizeof(struct locktab_s);
}

static lockelement*
lockelement_create(locktab *lt, gpointer key)
{
	lockelement *le;
	guint hashed_key;
	le = g_try_malloc0(sizeof(lockelement));
	if (!le)
		abort();
	le->key = lt->ctx.copy_key(key);
	hashed_key = lt->ctx.hash_key(key);
	le->ref_count = 1LU;
	le->owner = g_thread_self();
	le->cond = lt->cond_array[hashed_key % lt->cond_size];
	return le;
}

lockelement*
locktab_lock(locktab *lt, gpointer key)
{
	GThread *self;
	lockelement *le;

	self = g_thread_self();
	LOCKTAB_LOCK(lt);
	for (;;) {
		le = g_hash_table_lookup(lt->ht, key);
		if (!le) {
			le = lockelement_create(lt, key);
			g_hash_table_insert(lt->ht, le->key, le);
			break;
		}
		else if (!le->ref_count) {/*being closed elsewhere */
			LOCKELT_SIGNAL(le);
			LOCKELT_WAIT(lt,le);
		}
		else { /*not being closed, wait for no owner, and take it*/
			le->ref_count ++;
			while (le->owner && le->owner!=self)
				LOCKELT_WAIT(lt,le);
			le->owner = self;
			break;
		}
	}
	LOCKELT_SIGNAL(le);
	LOCKTAB_UNLOCK(lt);

	return le;
}

void
locktab_unlock(locktab *lt, gpointer key)
{
	GError *err = NULL;
	lockelement *le;

	LOCKTAB_LOCK(lt);
	le = g_hash_table_lookup(lt->ht, key);
	if (lt->checks_allowed) {
		GThread *self = g_thread_self();
		if (!le) {
			abort();
		}
		if (le->owner != self) {
			abort();
		}
	}

	le->ref_count --;
	LOCKELT_SIGNAL(le);
	
	if (le->ref_count)
		le->owner = NULL;
	else {
		if (lt->ctx.on_destroy) {
			LOCKTAB_UNLOCK(lt);
			lt->ctx.on_destroy(le, lt->ctx.ctx_data, &err);
			if (err)
				g_error_free(err);
			LOCKTAB_LOCK(lt);
		}

		/*now destroy the element itself*/
		g_hash_table_remove(lt->ht, le->key);
		if (lt->ctx.free_key)
			lt->ctx.free_key(le->key);
		memset(le, 0x00, sizeof(lockelement));
		g_free(le);
	}
	LOCKTAB_UNLOCK(lt);
}

void
locktab_init(locktab *lt, gsize nb_cond, struct locktab_ctx_s *ctx)
{
	if (!lt)
		return ;
	memset(lt, 0x00, sizeof(locktab));
	lt->ht = g_hash_table_new_full(ctx->hash_key, ctx->equal_key,
		NULL, NULL);
	lt->checks_allowed = ~0;
	LOCK_CREATE(lt->mutex);
	lt->cond_size = nb_cond;
	lt->cond_array = g_try_malloc0(nb_cond*sizeof(sync_cond_t *));
	if (!lt->cond_array)
		abort();
	while (nb_cond--)
		COND_CREATE(lt->cond_array[nb_cond]);
	if (ctx)
		memcpy(&(lt->ctx), ctx, sizeof(struct locktab_ctx_s));
}

void
locktab_fini(locktab *lt)
{
	gsize i;
	if (!lt)
		return;
	if (lt->ht) {
		g_hash_table_remove_all(lt->ht);
		g_hash_table_destroy(lt->ht);
		lt->ht = NULL;
	}
	if (lt->mutex) {
		LOCK_FREE(lt->mutex);
		lt->mutex = NULL;
	}
	if (lt->cond_array) {
		for (i=0; i<lt->cond_size ;i++)
			if (lt->cond_array[i])
				COND_FREE(lt->cond_array[i]);
		g_free(lt->cond_array);
		lt->cond_array = NULL;
	}
	lt->cond_size = 0;
}

gpointer
lockelement_get_key(lockelement *le)
{
	return le ? le->key : NULL;
}

gpointer
lockelement_get_user_data(lockelement *le)
{
	return le ? le->udata : NULL;
}

gpointer
lockelement_set_user_data(lockelement *le, gpointer u)
{
	gpointer save = u;
	if (le) {
		save = le->udata;
		le->udata = u;
	}
	return save;
}

