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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.namespace_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_NamespaceInfo.h"
#include "./asn_AddrInfo.h"
#include "./asn_Parameter.h"

static gboolean
list_conversion(
		const struct NamespaceInfoValueList *nsinfo_vlist,
		GHashTable **ht,
		GHashTable* (*conv_func)(GSList * pairs, GError ** err))
{
	g_assert (nsinfo_vlist != NULL);
	g_assert (ht != NULL);

	void _free(GSList *valuelist) {
		if (valuelist) {
			g_slist_foreach(valuelist, key_value_pair_gclean, NULL);
			g_slist_free(valuelist);
		}
		errno = ENOMEM;
	}

	if (nsinfo_vlist->list.count <= 0) {
		*ht = key_value_pairs_empty();
	} else {
		GSList* valuelist = NULL;
		GError *error = NULL;

		for (int i = 0; i < nsinfo_vlist->list.count; i++) {
			Parameter_t* asn_prop;
			key_value_pair_t* api_prop;

			if (!(asn_prop = nsinfo_vlist->list.array[i]))
				continue;
			if (!(api_prop = g_try_malloc0(sizeof(key_value_pair_t)))) {
				_free(valuelist);
				return FALSE;
			}
			if (!key_value_pair_ASN2API(asn_prop, api_prop)) {
				g_free(api_prop);
				_free(valuelist);
				return FALSE;
			}
			valuelist = g_slist_prepend(valuelist, api_prop);
		}

		*ht = (conv_func(valuelist, &error));
		g_slist_foreach(valuelist, key_value_pair_gclean, NULL);
		g_slist_free(valuelist);
		valuelist = NULL;

		if (*ht == NULL) {
			ERROR("Failed to convert key_value_pairs to map in namespace_info ASN to API conversion : %s",
					gerror_get_message(error));
			g_clear_error(&error);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
namespace_info_ASN2API(const NamespaceInfo_t *asn, namespace_info_t *api)
{
	if (!api || !asn)
		return FALSE;

	bzero(api, sizeof(*api));

	memcpy(api->name, asn->name.buf, MIN(LIMIT_LENGTH_NSNAME, asn->name.size));
	addr_info_ASN2API(&(asn->addr), &(api->addr));
	asn_INTEGER_to_int64(&(asn->chunkSize), &(api->chunk_size));

	if (!list_conversion(&(asn->options), &(api->options), key_value_pairs_convert_to_map))
		return FALSE;

	if (!list_conversion(&(asn->storagePolicy), &(api->storage_policy), key_value_pairs_convert_to_map))
		return FALSE;

	if (!list_conversion(&(asn->dataSecurity), &(api->data_security), key_value_pairs_convert_to_map))
		return FALSE;

	if (!list_conversion(&(asn->dataTreatments), &(api->data_treatments), key_value_pairs_convert_to_map))
		return FALSE;

	if (!list_conversion(&(asn->storageClass), &(api->storage_class), key_value_pairs_convert_to_map))
		return FALSE;

	return TRUE;

}

static gboolean
hashtable_conversion(GHashTable *ht,
		struct NamespaceInfoValueList *nsinfo_vlist,
		GSList* (*conv_func)(GHashTable *, gboolean, GError **))
{
	g_assert (ht != NULL);
	g_assert (nsinfo_vlist != NULL);
	g_assert (conv_func != NULL);

	GError *error = NULL;
	GSList* result = conv_func(ht, TRUE, &error);
	if (result == NULL && error != NULL) {
		ERROR("Failed to convert map to key_value_pairs in namespace_info API to ASN conversion : %s",
				gerror_get_message(error));
		g_clear_error(&error);
		return FALSE;
	}

	if (result != NULL) {
		/* fill the array */
		for (GSList *p = result; p != NULL; p = p->next) {
			key_value_pair_t* api_prop;
			Parameter_t* asn_prop;

			if (!(api_prop = (key_value_pair_t*)p->data))
				continue;
			if (!(asn_prop = g_try_malloc0(sizeof(Parameter_t))))
				continue;
			if (!key_value_pair_API2ASN(api_prop, asn_prop)) {
				g_free(asn_prop);
				continue;
			}
			asn_set_add(&(nsinfo_vlist->list), asn_prop);
		}

		/* free the temp list */
		g_slist_foreach(result, key_value_pair_gclean, NULL);
		g_slist_free(result);
	}

	return TRUE;
}

gboolean
namespace_info_API2ASN(const namespace_info_t * api, NamespaceInfo_t * asn)
{
	if (!api || !asn)
		return FALSE;

	OCTET_STRING_fromBuf(&(asn->name), api->name, MIN(strlen(api->name), LIMIT_LENGTH_NSNAME));
	addr_info_API2ASN(&(api->addr), &(asn->addr));
	asn_int64_to_INTEGER(&(asn->chunkSize), api->chunk_size);

	if (!hashtable_conversion(api->options, &(asn->options), key_value_pairs_convert_from_map))
		return FALSE;

	if(!hashtable_conversion(api->storage_policy, &(asn->storagePolicy), key_value_pairs_convert_from_map))
		return FALSE;

	if(!hashtable_conversion(api->data_security, &(asn->dataSecurity), key_value_pairs_convert_from_map))
		return FALSE;

	if(!hashtable_conversion(api->data_treatments, &(asn->dataTreatments), key_value_pairs_convert_from_map))
		return FALSE;

	if(!hashtable_conversion(api->storage_class, &(asn->storageClass), key_value_pairs_convert_from_map))
		return FALSE;

	errno = 0;
	return TRUE;
}

void
namespace_info_cleanASN(NamespaceInfo_t * asn, gboolean only_content)
{
	void parameter_cleanASN(Parameter_t * asn_param) {
		key_value_pair_cleanASN(asn_param, FALSE);
	}

	if (!asn) {
		errno = EINVAL;
		return;
	}

	asn->options.list.free = parameter_cleanASN;
	asn->storagePolicy.list.free = parameter_cleanASN;
	asn->dataSecurity.list.free = parameter_cleanASN;
	asn->dataTreatments.list.free = parameter_cleanASN;
	asn->storageClass.list.free = parameter_cleanASN;

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NamespaceInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_NamespaceInfo, asn);

	errno = 0;
}

