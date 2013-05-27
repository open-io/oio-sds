/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file storage_policy.h
 * Server Storage policy library
 */

#ifndef __STORAGE_POLICY__H__
# define __STORAGE_POLICY__H__ 1

/* DATA SECURITY KEYS */
#define DS_KEY_DISTANCE "distance"
#define DS_KEY_COPY_COUNT "nb_copy"

/* DATA TREATMENTS KEYS */
#define DT_KEY_BLOCKSIZE "blocksize"
#define DT_KEY_ALGO "algo"

#include "./metautils.h"

/**
 * @defgroup storage_policy
 * @ingroup server
 */

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

/**
 * Forward declaration
 */
struct data_security_s;

/**
 * Forward declaration
 */
struct data_treatments_s;

/**
 * Forward declaration
 */
struct storage_policy_s;

/**
 * @param ni
 * @param name
 * @return
 */
struct storage_policy_s * storage_policy_init(namespace_info_t *ni,
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
 * @param sp
 * @return
 */
const struct data_treatments_s *storage_policy_get_data_treatments(
		const struct storage_policy_s *sp);

/**
 * @param sp
 * @return
 */
const char* storage_policy_get_storage_class(const struct storage_policy_s *sp);

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

#endif /* __STORAGE_POLICY__H__ */
