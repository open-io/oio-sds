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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.stgpol"
#endif

#include <errno.h>
#include <string.h>
#include <glib.h>

#include "./storage_policy.h"
#include "./metautils.h"



struct data_security_s
{
	gchar *name;
	enum data_security_e type;
	GHashTable *params;
};

struct data_treatments_s
{
	gchar *name;
	enum data_treatments_e type;
	GHashTable *params;
};

struct storage_policy_s
{
	gchar *name;
	struct data_security_s *datasec;
	struct data_treatments_s *datatreat;
	gchar *stgclass;
};

/***********************************************************/

static void
_data_security_clean(struct data_security_s *ds)
{
	if(!ds)
		return;
	
	if(NULL != ds->name)
		g_free(ds->name);
	
	if(NULL != ds->params)
		g_hash_table_destroy(ds->params);

	g_free(ds);
}

static void
_data_treatments_clean(struct data_treatments_s *dt)
{
	if(!dt)
		return;
	
	if(NULL != dt->name)
		g_free(dt->name);
	
	if(NULL != dt->params)
		g_hash_table_destroy(dt->params);

	g_free(dt);
}

static void
__fill_info(GHashTable *params, const char *info)
{
	gchar **tok = NULL;
	tok = g_strsplit(info, "|", 0);
	for (uint i = 0; i < g_strv_length(tok); i++) {
		gchar **kv = g_strsplit(tok[i], "=", 2);
		if(g_strv_length(kv) == 2) {
			g_hash_table_insert(params, g_strdup(kv[0]), g_strdup(kv[1]));
		}
		g_strfreev(kv);
	}

	g_strfreev(tok);
}

static int
_parse_data_treatments(struct storage_policy_s *sp, const char *str)
{
	gchar **tok = NULL;
	tok = g_strsplit(str, ":", 2);
	if(g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return 0;
	}

	if (g_str_has_prefix(tok[0], "COMP")) {
		sp->datatreat->type = COMPRESSION;
	} else if (g_str_has_prefix(tok[0],"CYPHER")) {
		sp->datasec->type = CYPHER;
	} else {
		g_strfreev(tok);
		return 0;
	}
	sp->datatreat->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	__fill_info(sp->datatreat->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

static int
_parse_data_security(struct storage_policy_s *sp, const char *str)
{
	gchar **tok = NULL;
	tok = g_strsplit(str, ":", 2);
	if(g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return 0;
	}

	if (g_str_has_prefix(tok[0], "DUP")) {
		sp->datasec->type = DUPLI;
	} else if (g_str_has_prefix(tok[0],"RAIN")) {
		sp->datasec->type = RAIN;
	} else {
		g_strfreev(tok);
		return 0;
	}
	sp->datasec->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	__fill_info(sp->datasec->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

static int
_load_data_security(struct storage_policy_s *sp, const char *key, namespace_info_t *ni)
{
	int status = 0;
	gchar *datasec = NULL;

	sp->datasec = g_malloc0(sizeof(struct data_security_s));
	sp->datasec->name = g_strdup(key);

	if( (0 == g_ascii_strcasecmp(key, "NONE")) || (0 == g_ascii_strcasecmp(key, "OFF"))) {
		sp->datasec->type = DS_NONE;	
		return 1;
	}
	
	datasec = namespace_info_get_data_security(ni, key);
	if (datasec == NULL) {
		return 0;
	}

	status = _parse_data_security(sp, datasec);

	g_free(datasec);

	return status;
}

static int
_load_data_treatments(struct storage_policy_s *sp, const char *key, namespace_info_t *ni)
{
	int status = 0;
	gchar *datatreat = NULL; 

	sp->datatreat = g_malloc0(sizeof(struct data_treatments_s));
	sp->datatreat->name = g_strdup(key);

	if( (0 == g_ascii_strcasecmp(key, "NONE")) || (0 == g_ascii_strcasecmp(key, "OFF"))) {
		sp->datatreat->type = DT_NONE;	
		return 1;
	}

	datatreat = namespace_info_get_data_treatments(ni, key);
	if (datatreat == NULL) {
		return 0;
	}

	status = _parse_data_treatments(sp, datatreat);

	g_free(datatreat);
	return status;
}

static int
_load_storage_policy(struct storage_policy_s *sp, GByteArray *gba, namespace_info_t *ni)
{
	gchar *str = NULL;
	gchar **tok = NULL;
	str = g_strndup((gchar *)gba->data, gba->len);
	tok = g_strsplit(str, ":", 3);
	g_free(str);

	if(g_strv_length(tok) != 3) {
		g_strfreev(tok);
		return 0;
	}
	
	sp->stgclass = g_strdup(tok[0]);

	if(!_load_data_security(sp, tok[1], ni)) {
		g_strfreev(tok);
		return 0;
	}

	if(!_load_data_treatments(sp, tok[2], ni)) {
		g_strfreev(tok);
		return 0;
	}

	g_strfreev(tok);
	return 1;
}

static void
__kv_dup(gpointer k, gpointer v, gpointer out)
{
	GHashTable **r = (GHashTable **) out;
	g_hash_table_insert(*r, g_strdup((gchar*)k), g_strdup((gchar*)v));
}

static GHashTable *
__copy_params(GHashTable *params)
{
	GHashTable *r = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	g_hash_table_foreach(params, __kv_dup, &r);

	return r;
}

static struct data_security_s *
_data_security_dup(struct data_security_s *ds)
{
	struct data_security_s *r = NULL;

	r = g_malloc0(sizeof(struct data_security_s));

	if(NULL != ds->name)
		r->name = g_strdup(ds->name);
	r->type = ds->type;
	if(NULL != ds->params)
		r->params = __copy_params(ds->params);
	
	return r;
}

static struct data_treatments_s *
_data_treatments_dup(struct data_treatments_s *dt)
{
	struct data_treatments_s *r = NULL;

	r = g_malloc0(sizeof(struct data_treatments_s));

	if(NULL != dt->name)
		r->name = g_strdup(dt->name);
	r->type = dt->type;
	if(NULL != dt->params)
		r->params = __copy_params(dt->params);
	
	return r;
}

/***********************************************************/

struct storage_policy_s *
storage_policy_init(namespace_info_t *ni, const char *name)
{
	/* sanity check */
	if(!ni || !name)
		return NULL;

	GByteArray *gba = NULL;
	struct storage_policy_s *sp = NULL;	
	sp = g_malloc0(sizeof(struct storage_policy_s));
	sp->name = g_strdup(name);
	gba = g_hash_table_lookup(ni->storage_policy, name);
	if(gba == NULL) {
		/* set dirty flag, don't allow any getter */
		storage_policy_clean(sp);
		return NULL;
	}
	if(!_load_storage_policy(sp, gba, ni)) {
		/* set dirty flag, don't allow any getter */
		storage_policy_clean(sp);
		return NULL;
	}

	return sp;
}

struct storage_policy_s *
storage_policy_dup(const struct storage_policy_s *sp) 
{
	struct storage_policy_s *r = NULL;
	
	if(!sp)
		return NULL;

	r = g_malloc0(sizeof(struct storage_policy_s));

	if(NULL != sp->name)
		r->name = g_strdup(sp->name);
	if(NULL != sp->stgclass)
		r->stgclass = g_strdup(sp->stgclass);
	if(NULL != sp->datasec)
		r->datasec = _data_security_dup(sp->datasec);
	if(NULL != sp->datatreat)
		r->datatreat = _data_treatments_dup(sp->datatreat);

	return r;
}

void storage_policy_clean(struct storage_policy_s *sp)
{
	if(!sp)
		return;

	if(NULL != sp->name)
		g_free(sp->name);

	if(NULL != sp->stgclass)
		g_free(sp->stgclass);

	if(NULL != sp->datasec) {
		_data_security_clean(sp->datasec);
		sp->datasec = NULL;
	}

	if(NULL != sp->datatreat) {
		_data_treatments_clean(sp->datatreat);
		sp->datatreat = NULL;
	}

	g_free(sp);
}

void storage_policy_gclean(gpointer u, gpointer ignored)
{
	(void) ignored;
	storage_policy_clean((struct storage_policy_s*) u);
}

const char *
storage_policy_get_name(const struct storage_policy_s *sp)
{
	if (NULL != sp)
		return sp->name;
	return NULL;
}

const struct data_security_s *
storage_policy_get_data_security(const struct storage_policy_s *sp)
{
	if(NULL != sp)
		return sp->datasec;
	return NULL;
}

const struct data_treatments_s *
storage_policy_get_data_treatments(const struct storage_policy_s *sp)
{
	if(NULL != sp)
		return sp->datatreat;
	return NULL;
}

const char *
storage_policy_get_storage_class(const struct storage_policy_s *sp)
{
	if( NULL != sp)
		return sp->stgclass;
	return NULL;
}

enum data_security_e
data_security_get_type(const struct data_security_s *ds)
{
	if( NULL != ds)
		return ds->type;
	return DS_NONE;
}

const char *
data_security_get_param(const struct data_security_s *ds, const char *key)
{
	if(ds && ds->params)
		return g_hash_table_lookup(ds->params, key);
	
	return NULL;
}

enum data_treatments_e
data_treatments_get_type(const struct data_treatments_s *ds)
{
	if(NULL != ds)
		return ds->type;
	return DT_NONE;
}

const char *
data_treatments_get_param(const struct data_treatments_s *dt, const char *key)
{
	if(NULL != dt && NULL != dt->params)
		return g_hash_table_lookup(dt->params, key);
	
	return NULL;
}
