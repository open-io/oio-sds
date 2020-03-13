/*
OpenIO SDS core library
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__core__oioext_h
# define OIO_SDS__core__oioext_h 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <json-c/json.h>

// Return -1 if A<B, 0 if A==B, 1 if A>B
#define CMP(a,b) (((a) > (b)) - ((a) < (b)))

#define BOOL(C) ((C)!=0)

#define MACRO_COND(C,A,B) ((B) ^ (((A)^(B)) & -BOOL(C)))

#define OIO_TEST_INIT(argc,argv) oio_ext_init_test(&argc,&argv)
#define HC_TEST_INIT(argc,argv) OIO_TEST_INIT(argc,argv)

void oio_ext_init_test (int *argc, char ***argv);

/** Shuffles the single linked list. The original <src> MUST NOT be reused. */
GSList * oio_ext_gslist_shuffle(GSList *src);

/** Shuffles <array> in place. <len> is the len of the array. <len> must be
 * greater than 1. */
void oio_ext_array_shuffle (gpointer *array, gsize len);

/** Reuses the pointers of t0 and t1 to buuld a new NULL-terminated array */
void ** oio_ext_array_concat (void **t0, void **t1);

/** Sorts 'src' in place, placing first the items with a TRUE predicate
 * then the items with a FALSE predicate */
gsize oio_ext_array_partition (gpointer *array, gsize len,
		gboolean (*predicate)(gconstpointer));

struct oio_ext_json_mapping_s {
	const char *name;
	struct json_object **out;
	int type;
	unsigned int mandatory;
};

/** In one call, extract all the fields described in <tab> from the JSON
 * object j. */
GError * oio_ext_extract_json (struct json_object *j,
		struct oio_ext_json_mapping_s *tab);

/** Set a thread-local variable with a copy of the given request id. */
const char *oio_ext_set_reqid(const char *reqid);

/** Calls oio_ext_set_reqid() with a randomly generated string */
const char *oio_ext_set_random_reqid(void);

/** Calls oio_ext_set_reqid() with a randomly generated string,
 * with the specified prefix. */
const char *oio_ext_set_prefixed_random_reqid(const char *prefix);

/** If there is no request ID, generate one with the prefix, and return it.
 * If there is already one, return it. */
const char *oio_ext_ensure_reqid(const char *prefix);

/* DO NOT FREE ... In facts, DO NOT EVEN CONSIDER USING THIS FUNCTION!
 * Gets the PRNG associated to the local thread, and allocates on if none
 * already present. Returns THE pointer locally stored. Freeing it will break
 * things and make the world collapse. Freeing will cause Ragnarok, Mappo and
 * Al-Qiyamah all together. */
GRand * oio_ext_local_prng (void);

gboolean oio_ext_rand_boolean (void);

gdouble oio_ext_rand_double (void);

guint32 oio_ext_rand_int (void);

gint32 oio_ext_rand_int_range (gint32 low, gint32 up);

/** Get a request-id stored in the thread-local, or NULL if not set */
const char * oio_ext_get_reqid (void);

gint64 oio_ext_get_deadline(void);

void oio_ext_set_deadline(gint64 deadline);

gboolean oio_ext_is_admin(void);

void oio_ext_set_admin(const gboolean admin);

gboolean oio_ext_has_force_master(void);

void oio_ext_set_force_master(const gboolean force_master);

void oio_ext_set_upgrade_to_tls(const gboolean upgrade_to_tls);

gboolean oio_ext_has_upgrade_to_tls(void);

const gchar *oio_ext_get_user_agent(void);

void oio_ext_set_user_agent(const gchar *user_agent);

void oio_ext_clean_user_agent(void);

const gchar *oio_ext_get_force_versioning(void);

void oio_ext_set_force_versioning(const gchar *force_versioning);

void oio_ext_clean_force_versioning(void);

gboolean oio_ext_has_simulate_versioning(void);

void oio_ext_set_simulate_versioning(const gboolean simulate_versioning);

/** Enable or disable the performance data collection. */
GHashTable *oio_ext_enable_perfdata(gboolean enabled);

/** Get the performance data hash table (will be NULL when disabled) */
GHashTable *oio_ext_get_perfdata(void);

/** Add one metric in the performance data hash table.
 * Does not take ownership of the key.
 * When called several times with the same key, add values. */
void oio_ext_add_perfdata(const gchar *key, gint64 value);

gint64 oio_ext_real_time (void);

gint64 oio_ext_monotonic_time (void);

time_t oio_ext_real_seconds (void);

time_t oio_ext_monotonic_seconds (void);

gdouble oio_sys_cpu_idle (void);

gdouble oio_sys_io_idle (const char *vol);

gdouble oio_sys_space_idle (const char *vol);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oioext_h*/
