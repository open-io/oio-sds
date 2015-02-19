#ifndef __REDCURRANT_metatype_nsinfo__h
#define __REDCURRANT_metatype_nsinfo__h 1

#define REDC_LOSTFOUND_FOLDER "redc_lost+found"

struct namespace_info_s;

/**
 * @defgroup metautils_nsinfo NsInfo
 * @ingroup metautils_utils
 * @{
 */

/**
 * Find a namespace-prefixed key in a hash table. If key not found, try again
 * with parent VNS, and so on. If still not found, try unprefixed key.
 * Key may be NULL if the key is the namespace name.
 */
gpointer namespace_hash_table_lookup(GHashTable *table, const gchar *ns_name,
		const gchar *key);

/**
 * Get a parameter from the namespace info "options" hash table.
 * This intelligently looks for VNS overridden parameters.
 * If a service type is provided by the type-specific parameter
 * cannot be found, the generic parameter is tried.
 *
 * @param ni Pointer to the namespace info
 * @param ns_name Namespace or VNS name
 * @param srv_type The type of the service asking for this parameter
 *   (can be NULL)
 * @param param_name Name of the parameter to look for
 * @return The value or NULL
 */
GByteArray *namespace_info_get_srv_param_gba(const namespace_info_t *ni,
		const gchar *ns_name, const gchar *srv_type, const gchar *param_name);

/**
 * Same as namespace_info_get_srv_param_gba but converts the result
 * to int64.
 *
 * @param def The value to return when parameter is not found
 */
gint64 namespace_info_get_srv_param_i64(const namespace_info_t *ni,
		const gchar *ns_name, const gchar *srv_type, const gchar *param_name,
		gint64 def);

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

void namespace_info_reset(namespace_info_t *ni);
void namespace_info_init(namespace_info_t *ni);

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

struct json_object;

GError * namespace_info_init_json_object(struct json_object *obj,
		struct namespace_info_s *ni);

GError * namespace_info_init_json(const gchar *encoded,
		struct namespace_info_s *ni);

// Appends to 'out' a json representation of 'ni'
void namespace_info_encode_json(GString *out, struct namespace_info_s *ni);

/** @} */

#endif // __REDCURRANT_metatype_nsinfo__h
