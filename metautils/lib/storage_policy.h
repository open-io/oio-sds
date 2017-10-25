/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#define DS_KEY_ACCOUNT_ID "account_id"
#define DS_KEY_BUCKET_NAME "bucket_name"

#define STORAGE_POLICY_NONE "NONE"
#define DATA_SECURITY_NONE "NONE"

#define STGPOL_DSPREFIX_PLAIN "plain"
#define STGPOL_DSPREFIX_EC "ec"
#define STGPOL_DSPREFIX_BACKBLAZE "backblaze"

enum data_security_e
{
	STGPOL_DS_PLAIN,
	STGPOL_DS_EC,
	STGPOL_DS_BACKBLAZE
};

/** Forward declarations */
struct namespace_info_s;

/** Hidden types */
struct data_security_s;
struct storage_policy_s;

struct storage_policy_s * storage_policy_init(struct namespace_info_s *ni,
		const char *name);

/**
 * @param sp the storage policy
 * @return a string which represents the chunk method
 */
GString * storage_policy_to_chunk_method(const struct storage_policy_s *sp);

void storage_policy_clean(struct storage_policy_s *sp);

const char * storage_policy_get_name(const struct storage_policy_s *sp);

/** Get the number of chunks required to form a metachunk
 * (nb_copy for plain, k+m for EC). */
gint64 storage_policy_get_nb_chunks(const struct storage_policy_s *sp);

/** Get the minimum distance between chunks required by the storage policy. */
gint64 storage_policy_get_distance(const struct storage_policy_s *sp);

const struct data_security_s *storage_policy_get_data_security(
		const struct storage_policy_s *sp);

const gchar* storage_policy_get_service_pool(const struct storage_policy_s *sp);

enum data_security_e data_security_get_type(const struct data_security_s *ds);

const char * data_security_get_param(const struct data_security_s *ds,
		const char *key);

/** Get a data security parameter and converts it to gint64 (base 10). */
gint64 data_security_get_int64_param(const struct data_security_s *ds,
		const char *key, gint64 def);

#endif /*OIO_SDS__metautils__lib__storage_policy_h*/
