#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "lru.test"
#endif
#include "lrutree.h"

int
main(int argc, char **argv)
{
	struct lru_tree_s *lt;

	(void) argc;
	(void) argv;

	lt = lru_tree_create((GCompareFunc)g_strcmp0, g_free, NULL, 0);
	g_assert(lt != NULL);

	lru_tree_insert(lt, g_strdup("plop"), GINT_TO_POINTER(1));
	lru_tree_insert(lt, g_strdup("plop"), GINT_TO_POINTER(1));
	lru_tree_insert(lt, g_strdup("plip"), GINT_TO_POINTER(1));
	lru_tree_insert(lt, g_strdup("plup"), GINT_TO_POINTER(1));
	lru_tree_get(lt, "plop");
	lru_tree_get(lt, "plop");
	lru_tree_get(lt, "plop");
	lru_tree_get(lt, "plop");

	gpointer k, v;
	while (lru_tree_steal_first(lt, &k, &v)) {
		g_printerr("K %s %p\n", (gchar*)k, v);
		g_free(k);
	}

	lru_tree_destroy(lt);
	return 0;
}

