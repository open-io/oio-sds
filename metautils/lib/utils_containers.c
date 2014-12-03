#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils"
#endif

#include <stdlib.h>

#include "metautils_containers.h"

void
gslist_free_element(gpointer d, gpointer u)
{
	((GDestroyNotify) u) (d);
}

GSList *
gslist_split(GSList * list, gsize max)
{
	int i;
	GSList *sublist = NULL, *cursor = NULL, *ret = NULL;

	for (i = 1, cursor = list; cursor; cursor = cursor->next) {
		if (!cursor->data)
			continue;
		i++;
		sublist = g_slist_prepend(sublist, cursor->data);
		if (!(i % max)) {
			ret = g_slist_prepend(ret, sublist);
			sublist = NULL;
		}
	}
	if (sublist)
		ret = g_slist_prepend(ret, sublist);
	return ret;
}

void
gslist_chunks_destroy(GSList * list_of_lists, GDestroyNotify destroy_func)
{
	GSList *cursor;

	if (!list_of_lists)
		return;

	if (destroy_func) {
		for (cursor = list_of_lists; cursor; cursor = cursor->next) {
			GSList *nextList = (GSList *) cursor->data;

			if (!nextList)
				continue;
			g_slist_foreach(nextList, gslist_free_element, destroy_func);
			g_slist_free(nextList);
		}
	}
	else {
		for (cursor = list_of_lists; cursor; cursor = cursor->next) {
			GSList *nextList = (GSList *) cursor->data;

			if (!nextList)
				continue;
			g_slist_free(nextList);
		}
	}

	g_slist_free(list_of_lists);
}

#define PREPEND(Result,List) do { \
	next = (List)->next; \
	List->next = (Result); \
	(Result) = List; \
	List = next; \
} while (0)

static GSList*
gslist_merge_random(GSList *l1, GSList *l2)
{
	GSList *next, *result = NULL;

	while (l1 || l2) {
		if (l1 && l2) {
			if (rand() % 2)
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
		else {
			if (l1)
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
	}

	return result;
}

static void
gslist_split_in_two(GSList *src, GSList **r1, GSList **r2)
{
	GSList *next, *l1 = NULL, *l2 = NULL;

	while (src) {
		if (src)
			PREPEND(l1, src);
		if (src)
			PREPEND(l2, src);
	}

	*r1 = l1, *r2 = l2;
}

GSList *
metautils_gslist_shuffle(GSList *src)
{
	GSList *l1, *l2;

	gslist_split_in_two(src, &l1, &l2);
	return gslist_merge_random(
		(l1 && l1->next) ? metautils_gslist_shuffle(l1) : l1,
		(l2 && l2->next) ? metautils_gslist_shuffle(l2) : l2);
}

GSList*
metautils_array_to_list(void **orig)
{
	GSList *result = NULL;

	while (orig && *orig)
		result = g_slist_prepend(result, *(orig++));

	return g_slist_reverse(result);
}

GPtrArray*
metautils_list_to_gpa(GSList *orig)
{
	GPtrArray *gpa = g_ptr_array_new();
	for (; orig ; orig=orig->next)
		g_ptr_array_add(gpa, orig->data);
	g_ptr_array_add(gpa, NULL);
	return gpa;
}

void**
metautils_gpa_to_array(GPtrArray *orig, gboolean clean)
{
	if (!orig)
		return NULL;
	if (orig->len <= 0)
		return g_malloc0(sizeof(void**));
	if (NULL != orig->pdata[ orig->len - 1 ])
		g_ptr_array_add(orig, NULL);
	return clean ? g_ptr_array_free(orig, FALSE) : orig->pdata;
}

void**
metautils_list_to_array(GSList *orig)
{
	return metautils_gpa_to_array(metautils_list_to_gpa(orig), TRUE);
}

GSList*
metautils_gpa_to_list(GPtrArray *gpa)
{
	GSList *result = NULL;
	guint i;

	for (i=0; i < gpa->len ;i++) {
		if (gpa->pdata[i])
			result = g_slist_prepend(result, gpa->pdata[i]);
	}

	return g_slist_reverse(result);
}

void
g_slist_free_agregated(GSList * list2)
{
	GSList *cursor2;

	for (cursor2 = list2; cursor2; cursor2 = cursor2->next)
		g_slist_free((GSList *) (cursor2->data));
	g_slist_free(list2);
}

void
g_slist_foreach_agregated(GSList * list2, GFunc callback, gpointer user_data)
{
	GSList *cursor2;

	for (cursor2 = list2; cursor2; cursor2 = cursor2->next)
		g_slist_foreach((GSList *) (cursor2->data), callback, user_data);
}

GSList *
g_slist_agregate(GSList * list, GCompareFunc comparator)
{
	GSList *resL2 = NULL;	/*a list of lists of chunk_info_t */
	GSList *sorted = NULL;	/*a list of chunk_info_t */
	GSList *cursor1 = NULL;
	GSList *last_agregate = NULL;

	if (!list)
		return NULL;

	sorted = g_slist_copy(list);
	if (!sorted)
		return NULL;
	sorted = g_slist_sort(sorted, comparator);
	if (!sorted)
		return NULL;

	for (cursor1 = sorted; cursor1; cursor1 = cursor1->next) {
		if (!cursor1->data)
			continue;
		if (last_agregate && 0 > comparator(last_agregate->data, cursor1->data)) {
			resL2 = g_slist_prepend(resL2, last_agregate);
			last_agregate = NULL;
		}
		last_agregate = g_slist_prepend(last_agregate, cursor1->data);
	}

	if (last_agregate)
		resL2 = g_slist_prepend(resL2, last_agregate);

	g_slist_free (sorted);
	return g_slist_reverse(resL2);
}

GPtrArray*
metautils_gtree_to_gpa(GTree *t, gboolean clean)
{
	gboolean run_move(gpointer k, gpointer v, gpointer u) {
		(void) k;
		g_ptr_array_add(u, v);
		return FALSE;
	}
	GPtrArray *tmp = g_ptr_array_new();
	g_tree_foreach(t, run_move, tmp);
	if (clean)
		g_tree_destroy(t);
	return tmp;
}

