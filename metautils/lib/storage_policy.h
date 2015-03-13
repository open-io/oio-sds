/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__storage_policy_h
# define OIO_SDS__metautils__lib__storage_policy_h 1

/**
 * @defgroup storage_policy
 * @ingroup server
 */

/* DATA SECURITY KEYS */
#define DS_KEY_DISTANCE "distance"
#define DS_KEY_COPY_COUNT "nb_copy"
#define DS_KEY_K "k"
#define DS_KEY_M "m"
#define DS_KEY_ALGO "algo"

/* DATA TREATMENTS KEYS */
#define DT_KEY_BLOCKSIZE "blocksize"
#define DT_KEY_ALGO "algo"

#define STORAGE_POLICY_NONE "NONE"

#define STORAGE_CLASS_ANY "DUMMY"
#define STORAGE_CLASS_NONE "NONE"

#define DATA_TREATMENT_NONE "NONE"
#define DATA_TREATMENT_OFF "OFF"

#define DATA_SECURITY_NONE "NONE"
#define DATA_SECURITY_OFF "OFF"

enum data_security_e
{
	DUPLI=1,
	RAIN,
	DS_NONE,
};

enum data_treatments_e
{
	COMPRESSION=1,
	CYPHER,
	DT_NONE,
};

/** Forward declarations */
struct namespace_info_s;

/** Hidden types */
struct data_security_s;
struct data_treatments_s;
struct storage_policy_s;
struct storage_class_s;

/**
 * @param ni
 * @param name
 * @return
 */
struct storage_policy_s * storage_policy_init(struct namespace_info_s *ni,
		const char *name);

/**
 * @param sp the storage policy to duplicate
 * @return
 */
struct storage_policy_s * storage_policy_dup(const struct storage_policy_s *sp);

/**
 * @param sp
 */
void storage_policy_clean(struct storage_policy_s *sp);

/**
 * @param u
 * @param ignored
 */
void storage_policy_gclean(gpointer u, gpointer ignored);

/**
 * @param sp
 * @return
 */
const char * storage_policy_get_name(const struct storage_policy_s *sp);

/**
 * @parap sp
 * @return
 */
const struct data_security_s *storage_policy_get_data_security(
		const struct storage_policy_s *sp);

/**
 * Get the name of a data security type.
 *
 * @return The name of the data security type (static string, do not free)
 */
const gchar *data_security_type_name(enum data_security_e type);

/**
 * @param sp
 * @return
 */
const struct data_treatments_s *storage_policy_get_data_treatments(
		const struct storage_policy_s *sp);

/** Inits a storage class from scratch, with its namespace configuration. */
struct storage_class_s * storage_class_init (struct namespace_info_s *ni,
		const char *name);

/** Frees all the internal memory used by the storage class pointed by <sc> */
void storage_class_clean(struct storage_class_s *sc);

/** Calls storage_class_clean() on <u> and ignores <ignored> */
void storage_class_gclean(gpointer u, gpointer ignored);

/**
 * @param sp
 * @return
 */
const struct storage_class_s* storage_policy_get_storage_class(const struct storage_policy_s *sp);

/**
 * Get the name of a data security.
 *
 * @param ds
 * @return
 */
const gchar * data_security_get_name(const struct data_security_s *ds);

/**
 * @param ds
 * @return
 */
enum data_security_e data_security_get_type(const struct data_security_s *ds);

/**
 * @param ds
 * @param key
 * @return
 */
const char * data_security_get_param(const struct data_security_s *ds,
		const char *key);

/**
 * Get a data security parameter and converts it to gint64 (base 10).
 *
 * @param def Default value to return in case of error
 */
gint64 data_security_get_int64_param(const struct data_security_s *ds,
		const char *key, gint64 def);

/**
 * @param ds
 * @return
 */
enum data_treatments_e data_treatments_get_type(const struct data_treatments_s *ds);

/**
 * @param ds
 * @param key
 * @return
 */
const char * data_treatments_get_param(const struct data_treatments_s *ds,
		const char *key);

/**
 * Get the name of a storage class.
 *
 * @param sc Storage class instance
 * @return The name of the storage class or NULL
 */
const gchar * storage_class_get_name(const struct storage_class_s *sc);

/**
 * Get the list of storage class fallbacks.
 *
 * @param sc Storage class instance
 * @return The list of storage classes (gchar*)
 *     that can replace the current one
 */
const GSList * storage_class_get_fallbacks(const struct storage_class_s *sc);

/**
 * Does a storage class satisfies the requirements of another ?
 *
 * This function compares the storage class names, it does not
 * look at the fallback list. A wanted storage class STORAGE_CLASS_NONE,
 * STORAGE_CLASS_ANY or NULL is always satisfied.
 *
 * @param wsc Wanted storage class (gchar *)
 * @param asc Actual storage class (gchar *)
 * @return TRUE if asc satisfies wsc, FALSE otherwise
 */
gboolean storage_class_is_satisfied(const gchar *wsc, const gchar *asc);

/**
 * Does a storage class (string) satisfies the requirements of another ?
 *
 * @param wsc Wanted storage class (storage_class_t)
 * @param asc Actual storage class (gchar *)
 * @param strict Match exactly (by name)
 * @return TRUE if asc satisfies wsc, FALSE otherwise
 */
gboolean storage_class_is_satisfied2(const struct storage_class_s *wsc,
		const gchar *asc, gboolean strict);

/**
 * Check the chunk compatibility of two storage policies (by name), i.e. if
 * it is possible to change the policy without re-uploading the chunks.
 *
 * @return NULL on success, a GError otherwise
 */
GError *storage_policy_check_compat_by_name(struct namespace_info_s *ni,
		const gchar *old_stgpol, const gchar *new_stgpol);

/**
 * Check the chunk compatibility of two storage policies, i.e. if
 * it is possible to change the policy without re-uploading the chunks.
 *
 * @return NULL on success, a GError otherwise
 */
GError *storage_policy_check_compat(struct storage_policy_s *old_pol,
		struct storage_policy_s *new_pol);

/*
 * Extract the storage policy from a content sys-metadata
 * @param sys_metadata the metadata to process
 * @param storage_policy a pointer to the result
 * @result a gerror if an error occured, NULL otherwise
 *
 */
GError* storage_policy_from_metadata(GByteArray *sys_metadata, gchar **storage_policy);

/*
 * Extract the storage policy from a content sys-metadata
 * @param sys_metadata the metadata to process
 * @param storage_policy a pointer to the result
 * @result the matching storage policy if specified, NULL otherwise
 *
 */
char* storage_policy_from_mdsys_str(const char *mdsys);

/**
 * Compute the distance between two string representing rawx locations
 */
guint distance_between_location(const gchar *loc1, const gchar *loc2);

/**
 *
 */
guint distance_between_services(struct service_info_s *s0,
		struct service_info_s *s1);

/** @} */

#endif /*OIO_SDS__metautils__lib__storage_policy_h*/