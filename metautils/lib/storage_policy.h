/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#define DS_KEY_DISTANCE "distance"
#define DS_KEY_COPY_COUNT "nb_copy"
#define DS_KEY_K "k"
#define DS_KEY_M "m"
#define DS_KEY_ALGO "algo"
#define DS_KEY_WEAK "weak"

#define STORAGE_POLICY_NONE "NONE"
#define STORAGE_CLASS_NONE "NONE"
#define DATA_SECURITY_NONE "NONE"

#define STGPOL_DSPREFIX_PLAIN "plain"
#define STGPOL_DSPREFIX_EC "ec"

enum data_security_e
{
	STGPOL_DS_PLAIN,
	STGPOL_DS_EC,
};

/** Forward declarations */
struct namespace_info_s;

/** Hidden types */
struct data_security_s;
struct storage_policy_s;
struct storage_class_s;

struct storage_policy_s * storage_policy_init(struct namespace_info_s *ni,
		const char *name);

struct storage_policy_s * storage_policy_dup(const struct storage_policy_s *sp);

/**
 * @param sp the storage policy
 * @return a string which represents the storage policy
 */
GString * storage_policy_to_chunk_method(const struct storage_policy_s *sp);

void storage_policy_clean(struct storage_policy_s *sp);

const char * storage_policy_get_name(const struct storage_policy_s *sp);

/** Get the number of chunks required to form a metachunk
 * (nb_copy for plain, k+m for EC). */
gint64 storage_policy_get_nb_chunks(const struct storage_policy_s *sp);

const struct data_security_s *storage_policy_get_data_security(
		const struct storage_policy_s *sp);

/** Inits a storage class from scratch, with its namespace configuration. */
struct storage_class_s * storage_class_init (struct namespace_info_s *ni,
		const char *name);

/** Frees all the internal memory used by the storage class pointed by <sc> */
void storage_class_clean(struct storage_class_s *sc);

const struct storage_class_s* storage_policy_get_storage_class(const struct storage_policy_s *sp);

enum data_security_e data_security_get_type(const struct data_security_s *ds);

const char * data_security_get_param(const struct data_security_s *ds,
		const char *key);

/** Get a data security parameter and converts it to gint64 (base 10). */
gint64 data_security_get_int64_param(const struct data_security_s *ds,
		const char *key, gint64 def);

/** Get the name of a storage class. */
const gchar * storage_class_get_name(const struct storage_class_s *sc);

/** Get the list of storage class names that can be used as fallbacks. */
const GSList * storage_class_get_fallbacks(const struct storage_class_s *sc);

/**
 * Does a storage class satisfies the requirements of another ?
 *
 * This function compares the storage class names, it does not
 * look at the fallback list. A wanted storage class STORAGE_CLASS_NONE
 * or NULL is always satisfied.
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

#endif /*OIO_SDS__metautils__lib__storage_policy_h*/
