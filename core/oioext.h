/*
OpenIO SDS core library
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

#ifndef OIO_SDS__core__oioext_h
# define OIO_SDS__core__oioext_h 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <json-c/json.h>

# ifdef HAVE_NO_SLICE
#  define SLICE_NEW0(T)    g_try_new0(T,1)
#  define SLICE_NEW(T)     g_try_new(T,1)
#  define SLICE_ALLOC0(S)  g_try_malloc0(S)
#  define SLICE_ALLOC(S)   g_try_malloc(S)
#  define SLICE_FREE(T,P)  g_free(P)
#  define SLICE_FREE1(S,P) g_free(P)
# else
#  define SLICE_NEW0(T)    g_slice_new0(T)
#  define SLICE_NEW(T)     g_slice_new(T)
#  define SLICE_ALLOC0(S)  g_slice_alloc0(S)
#  define SLICE_ALLOC(S)   g_slice_alloc(S)
#  define SLICE_FREE(T,P)  g_slice_free(T,(P))
#  define SLICE_FREE1(S,P) g_slice_free1((S),(P))
# endif

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
void oio_ext_set_reqid (const char *reqid);

/** Calls oio_ext_set_reqid() with a randomly generated string */
void oio_ext_set_random_reqid (void);

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
