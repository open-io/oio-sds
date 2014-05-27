#ifndef __REDCURRANT_metatype_nsinfo__h
#define __REDCURRANT_metatype_nsinfo__h 1

#define DUMMY_STORAGE_CLASS "DUMMY"
#define REDC_LOSTFOUND_FOLDER "redc_lost+found"

struct namespace_info_s;

/**
 * @defgroup metautils_nsinfo NsInfo
 * @ingroup metautils_utils
 * @{
 */

/**
 * Copy a namespace_info into another namespace_info
 *
 * The option hashtable is not copied. The old table's reference
 * count is decremented (then the table will e destroyed if it falls
 * to zero), and the table of the new struct namespace_info_s will be
 * referenced in the destination structure.
 *
 * @param src the source namespace_info we copy from
 * @param dst the destination namespace_info we copy to
 * @param error
 * @return FALSE if an error occured, TRUE otherwise
 */
gboolean namespace_info_copy(struct namespace_info_s* src,
		struct namespace_info_s* dst, GError **error);


/**
 * Makes a deep copy of the input struct namespace_info_s.
 *
 * Contrary to namespace_info_copy(), the options table will be
 * newly allocated and filled with newly allocated values.
 *
 * @param src the struct namespace_info_s to be dupplicated
 * @param error
 *
 * @return NULL in case of error, or a valid struct namespace_info_s
 */
struct namespace_info_s* namespace_info_dup(struct namespace_info_s* src,
		GError **error);


/**
 * Clear a namespace_info content
 *
 * @param ns_info the namespace_info to clear
 */
void namespace_info_clear(struct namespace_info_s* ns_info);


/**
 * Free a namespace_info pointer
 *
 * @param ns_info the namespace_info to free
 */
void namespace_info_free(struct namespace_info_s* ns_info);


/**
 * Calls namespace_info_free() on p1 and ignores p2.
 *
 * Mainly used with g*list_foreach() functions of the GLib2
 * to clean at once whole lists of namespace_info_s structures.
 */
void namespace_info_gclean(gpointer p1, gpointer p2);


/** 
 * Map the given list of struct namespace_info_s in a GHashTable
 * where the values are the list elements (not a copy!)
 * and where the keys are the "name" fields the the values.
 */
GHashTable* namespace_info_list2map(GSList *list_nsinfo, gboolean auto_free);


/**
 * Return the list of the namespace names contained in
 * the namespace_info_s elements of the input list.
 * If copy is TRUE, then the returned list contains newly allocated
 * string elements, that should be freed with g_free().
 *
 * The sequence order of the result list does not reflect the
 * sequence order of the input list, and the duplicated entries.
 */
GSList* namespace_info_extract_name(GSList *list_nsinfo, gboolean copy);


/**
 * Get the data_security definition from the specified key
 */
gchar * namespace_info_get_data_security(struct namespace_info_s *ni,
		const gchar *data_sec_key);

/**
 * Get the data_treatments definition from the specified key
 */
gchar * namespace_info_get_data_treatments(struct namespace_info_s *ni,
		const gchar *data_treat_key);

/**
 * Returns whether the given VNS is writable or not.
 * @param ni namespace info
 * @param vns VNS name
 * @return TRUE if VNS is writable, FALSE otherwise
 */
gboolean namespace_info_is_vns_writable(struct namespace_info_s *ni,
		const gchar *vns);

/**
 * Get the storage_class definition from the specified key
 */
gchar * namespace_info_get_storage_class(struct namespace_info_s *ni,
		const gchar *stgclass_key);

/** @} */

#endif // __REDCURRANT_metatype_nsinfo__h
