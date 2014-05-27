#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.lrutree"
#endif

#include "./tree.h"
#include "./lrutree.h"

struct _node_s
{
    RB_ENTRY(_node_s) entry;
    struct _node_s *prev;
    struct _node_s *next;

    gpointer k;
    gpointer v;
};

struct lru_tree_s
{
    GCompareFunc kcmp;
    GDestroyNotify kfree;
    GDestroyNotify vfree;
    guint32 flags;

	gint64 count;

	// Red-Black tree 'by key'
    RB_HEAD(_tree_s, _node_s) base;

	// LRU double-ended queue
    struct _node_s *first;
    struct _node_s *last;
};

/* Nodes handling ---------------------------------------------------------- */

static void
_node_cleanup(struct lru_tree_s *lt, struct _node_s *node)
{
    if (lt->vfree && node->v)
        lt->vfree(node->v);
    if (lt->kfree && node->k)
        lt->kfree(node->k);
    node->k = node->v = NULL;
}

static int
_node_compare(gpointer u, struct _node_s *n0, struct _node_s *n1)
{
    struct lru_tree_s *lt = u;
    return lt->kcmp(n0->k, n1->k);
}

static struct _node_s*
_node_create(gpointer k, gpointer v)
{
    struct _node_s *n = g_malloc0(sizeof(struct _node_s));
    n->k = k;
    n->v = v;
    return n;
}

static void
_node_destroy(struct lru_tree_s *lt, struct _node_s *node)
{
    _node_cleanup(lt, node);
    g_free(node);
}

static void
_node_update(struct lru_tree_s *lt, struct _node_s *node, gpointer k,
        gpointer v)
{
    _node_cleanup(lt, node);
    node->k = k;
    node->v = v;
}

static void
_node_deq_extract(struct lru_tree_s *lt, struct _node_s *node)
{
    // special case if the node is first or last
    if (lt->first == node)
        lt->first = node->next;
    if (lt->last == node)
        lt->last = node->prev;

    // Now do local ring removal
    if (node->prev)
        node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;

    node->next = node->prev = NULL;
}

static void
_node_deq_push_front(struct lru_tree_s *lt, struct _node_s *node)
{
    if (!lt->first) {
        node->prev = node->next = NULL;
        lt->first = lt->last = node;
    }
    else {
        node->prev = NULL;
        node->next = lt->first;
        lt->first->prev = node;
        lt->first = node;
    }
}

/* Red-Black tree handling ------------------------------------------------- */

RB_PROTOTYPE_STATIC(_tree_s, _node_s, entry, _node_compare);

RB_GENERATE_STATIC(_tree_s, _node_s, entry, _node_compare);

/* Main structure handling ------------------------------------------------- */

struct lru_tree_s*
lru_tree_create(GCompareFunc cmp, GDestroyNotify kfree, GDestroyNotify vfree,
        guint32 options)
{
    struct lru_tree_s *lt = g_malloc0(sizeof(struct lru_tree_s));
    lt->kcmp = cmp;
    lt->kfree = kfree;
    lt->vfree = vfree;
    lt->flags = options;
    RB_INIT(&(lt->base));

    return lt;
}

void
lru_tree_destroy(struct lru_tree_s *lt)
{
    if (!lt)
        return;

	while (lt->first) {
		struct _node_s *n = lt->first;
		if (NULL != (lt->first = n->next))
			lt->first->prev = NULL;
		_node_destroy(lt, n);
	}

    g_free(lt);
}

void
lru_tree_insert(struct lru_tree_s *lt, gpointer k, gpointer v)
{
    struct _node_s fake, *node;

    g_assert(lt != NULL);
    g_assert(k != NULL);
    g_assert(v != NULL);

    fake.k = k;
    if (!(node = RB_FIND(_tree_s, lt, &(lt->base), &fake))) {
        node = _node_create(k, v);
        RB_INSERT(_tree_s, lt, &(lt->base), node);
		++ lt->count;
    }
    else {
        _node_deq_extract(lt, node);
        _node_update(lt, node, k, v);
    }

    _node_deq_push_front(lt, node);
}

gpointer
lru_tree_get(struct lru_tree_s *lt, gconstpointer k)
{
    struct _node_s fake, *node;

    g_assert(lt != NULL);
    g_assert(k != NULL);

    fake.k = k;
    node = RB_FIND(_tree_s, lt, &(lt->base), &fake);

    if (!node)
        return NULL;

    if (!(lt->flags & LTO_NOATIME)) {
        _node_deq_extract(lt, node);
        _node_deq_push_front(lt, node);
    }

    return node->v;
}

gboolean
lru_tree_remove(struct lru_tree_s *lt, gconstpointer k)
{
    struct _node_s fake, *node;

    g_assert(lt != NULL);
    g_assert(k != NULL);

    fake.k = k;
    if (!(node = RB_FIND(_tree_s, lt, &(lt->base), &fake)))
        return FALSE;

    RB_REMOVE(_tree_s, &(lt->base), node);
    _node_deq_extract(lt, node);
	-- lt->count;

    _node_destroy(lt, node);
    return TRUE;
}

gpointer
lru_tree_steal(struct lru_tree_s *lt, gconstpointer k)
{
    struct _node_s fake, *node;
    gpointer result;

    g_assert(lt != NULL);
    g_assert(k != NULL);

    fake.k = k;
    if (!(node = RB_FIND(_tree_s, lt, &(lt->base), &fake)))
        return NULL;

    RB_REMOVE(_tree_s, &(lt->base), node);
    _node_deq_extract(lt, node);
	-- lt->count;

    result = node->v;
    node->v = NULL;
    _node_destroy(lt, node);
    return result;
}

static gboolean
_get(struct lru_tree_s *lt, gpointer *pk, gpointer *pv, struct _node_s *node,
        int steal)
{
    g_assert(pk != NULL);
    g_assert(pv != NULL);

    if (!node)
        return FALSE;

    // steal the values
    *pk = node->k;
    *pv = node->v;

    if (steal) { // clean the structures
        node->k = node->v = NULL;
        RB_REMOVE(_tree_s, &(lt->base), node);
        _node_deq_extract(lt, node);
        _node_destroy(lt, node);
		-- lt->count;
    }
    else if (!(lt->flags & LTO_NOATIME)) {
        _node_deq_extract(lt, node);
        _node_deq_push_front(lt, node);
    }

    return TRUE;
}

gboolean
lru_tree_get_first(struct lru_tree_s *lt, gpointer *pk, gpointer *pv)
{
    g_assert(lt != NULL);
    return _get(lt, pk, pv, lt->first, 0);
}

gboolean
lru_tree_steal_first(struct lru_tree_s *lt, gpointer *pk, gpointer *pv)
{
    g_assert(lt != NULL);
    return _get(lt, pk, pv, lt->first, 1);
}

gboolean
lru_tree_get_last(struct lru_tree_s *lt, gpointer *pk, gpointer *pv)
{
    g_assert(lt != NULL);
    return _get(lt, pk, pv, lt->last, 0);
}

gboolean
lru_tree_steal_last(struct lru_tree_s *lt, gpointer *pk, gpointer *pv)
{
    g_assert(lt != NULL);
    return _get(lt, pk, pv, lt->last, 1);
}

void
lru_tree_foreach_TREE(struct lru_tree_s *lt, GTraverseFunc h, gpointer hdata)
{
	struct _node_s *node = NULL;

	g_assert(lt != NULL);
	g_assert(h != NULL);

	RB_FOREACH(node, _tree_s, &(lt->base)) {
		if (h(node->k, node->v, hdata))
			return;
	}
}

void
lru_tree_foreach_DEQ(struct lru_tree_s *lt, GTraverseFunc h, gpointer hdata)
{
	struct _node_s *node = NULL;

	g_assert(lt != NULL);
	g_assert(h != NULL);

	for (node = lt->first; node ;node=node->next) {
		if (h(node->k, node->v, hdata))
			return;
	}
}

gint64
lru_tree_count(struct lru_tree_s *lt)
{
	g_assert(lt != NULL);
	return lt->count;
}

