#ifndef __REDCURRANT__metautils_containers__h
# define __REDCURRANT__metautils_containers__h 1

#include <glib.h>

/**
 * Builds a NULL-terminated array with the pointers extracted from orig.
 *
 * @param orig
 * @return
 */
void** metautils_list_to_array(GSList *orig);

/**
 * @param orig
 * @return
 */
GPtrArray* metautils_list_to_gpa(GSList *orig);

/**
 * @param gpa
 * @return
 */
GSList* metautils_gpa_to_list(GPtrArray *gpa);

/** Convert an array of pointer to a signly linked list, omitting the last
 * NULL beacon. */
GSList* metautils_array_to_list(void **orig);

void** metautils_gpa_to_array(GPtrArray *orig, gboolean clean);

GPtrArray* metautils_gtree_to_gpa(GTree *t, gboolean clean);

GSList * metautils_gslist_shuffle(GSList *src);

/**
 * Split a GSList in a list of GSList each containg a max elements
 *
 * @param list a GSList to split
 * @param max the max number of element in each sublist
 *
 * @return a GSList of all splitted lists
 */
GSList *gslist_split(GSList * list, gsize max);


/**
 * Convinient func to use with g_slist_foreach
 * Pass the clean func has data arguement */
void gslist_free_element(gpointer d, gpointer u);


/**
 * Frees a list of lists, at least the list elements structures and also
 * their elements if the destructor callback has been provided.
 * 
 * Assumes the list parameter itself contains lists (a GSList* of GSlist*).
 *
 * @param list_of_lists a single linked list (may be NULL)
 * @param destroy_func a desturctor function pointer
 */
void gslist_chunks_destroy(GSList * list_of_lists, GDestroyNotify destroy_func);


/**
 * agregate the given list of chunk_info_t
 * the chunks with the same position will be grouped in a sublist.
 * The result will then be a list of lists of chunk_info_t with the
 * same position field.
 *
 * @param list
 * @param comparator
 * @return
 */
GSList *g_slist_agregate(GSList * list, GCompareFunc comparator);


/**
 * frees the list of lists and all the sublists
 *
 * @param list2
 */
void g_slist_free_agregated(GSList * list2);


/**
 * Runs all the elements of the sublist, and applies the callback
 * with the given user_data on each element.
 *
 * @param list
 * @param callback
 * @param user_data
 */
void g_slist_foreach_agregated(GSList * list, GFunc callback, gpointer user_data);

#endif // __REDCURRANT__metautils_containers__h
