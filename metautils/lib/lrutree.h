#ifndef HC_lru_tree__h
# define HC_lru_tree__h 1
# include <glib.h>

#define LTO_NONE	0x00
#define LTO_NOATIME 0X01

struct lru_tree_s;

/**
 * @param compare
 * @param kfree
 * @param vfree
 * @param options a binary OR'ed combination of LTO_* flags.
 * @return NULL in case of error or a valid lru_tree_s ready to be used
 */
struct lru_tree_s* lru_tree_create(GCompareFunc compare,
		GDestroyNotify kfree, GDestroyNotify vfree, guint32 options);

/**
 * Destroys the LRU-Tree and calls the liberation hook for each stored
 * pair.
 *
 * @param lt may be NULL
 */
void lru_tree_destroy(struct lru_tree_s *lt);

/**
 * Associates 'k' with 'v' in this container.
 *
 * @param lt not NULL
 * @param k not NULL
 * @param v noy NULL
 */
void lru_tree_insert(struct lru_tree_s *lt, gpointer k, gpointer v);

/**
 * @param lt not NULL
 * @param k not NULL
 * @return the value associated to 'k'
 */
gpointer lru_tree_get(struct lru_tree_s *lt, gconstpointer k);

/**
 * @param lt not NULL
 * @param k not NULL
 * @return FALSE if removed or something else if the v has been removed.
 */
gboolean lru_tree_remove(struct lru_tree_s *lt, gconstpointer k);

/**
 * @param lt not NULL
 * @param k not NULL
 * @return NULL if not found or the 'v' associated to k
 */
gpointer lru_tree_steal(struct lru_tree_s *lt, gconstpointer k);

/**
 * @param lt not NULL
 * @param pk not NULL
 * @param pv not NULL
 * @return TRUE is pk and pv set
 */
gboolean lru_tree_get_first(struct lru_tree_s *lt, gpointer *pk,
		gpointer *pv);

/**
 * @param lt not NULL
 * @param pk not NULL
 * @param pv not NULL
 * @return TRUE is pk and pv set
 */
gboolean lru_tree_steal_first(struct lru_tree_s *lt, gpointer *pk,
		gpointer *pv);

/**
 * @param lt not NULL
 * @param pk not NULL
 * @param pv not NULL
 * @return TRUE is pk and pv set
 */
gboolean lru_tree_get_last(struct lru_tree_s *lt, gpointer *pk,
		gpointer *pv);

/**
 * @param lt not NULL
 * @param pk not NULL
 * @param pv not NULL
 * @return TRUE is pk and pv set
 */
gboolean lru_tree_steal_last(struct lru_tree_s *lt, gpointer *pk,
		gpointer *pv);

/**
 * Run the elements according to the TREE order, i.e. the order got from the
 * comparison function.
 *
 * @param lt not NULL
 * @param h a not NULL hook to be called on each tree element
 * @param hdata a (maybe NULL) arbitrary argument passed to each hook call.
 */
void lru_tree_foreach_TREE(struct lru_tree_s *lt, GTraverseFunc h, gpointer hdata);

/**
 * Run the elementsaccording to their last access order. The last element
 * will be the LRU elements.
 *
 * @see lru_tree_foreach()
 * @param h a not NULL hook to be called on each 2queue element
 * @param hdata a (maybe NULL) arbitrary argument passed to each hook call.
 */
void lru_tree_foreach_DEQ(struct lru_tree_s *lt, GTraverseFunc h, gpointer hdata);

/**
 * @param lt not NULL
 * @return the number of elements in lt
 */
gint64 lru_tree_count(struct lru_tree_s *lt);

#endif /* HC_lru_tree__h */
