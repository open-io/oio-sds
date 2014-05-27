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
		GHashTable* (*conv_func)(GSList * pairs, gboolean copy, GError ** err))
{
	void _free(GSList *valuelist) {
		if (valuelist) {
			g_slist_foreach(valuelist, key_value_pair_gclean, NULL);
			g_slist_free(valuelist);
		}
		errno = ENOMEM;
	}

	if (nsinfo_vlist->list.count > 0) {
		int i;
		GSList* valuelist = NULL;
		GError *error = NULL;

		for (i = 0; i < nsinfo_vlist->list.count; i++) {
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

		*ht = (conv_func(valuelist, TRUE, &error));
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

	if (!list_conversion(&(asn->options), &(api->options), key_value_pairs_convert_to_map))
		return FALSE;

	memcpy(api->name, asn->name.buf, MIN(LIMIT_LENGTH_NSNAME, asn->name.size));
	addr_info_ASN2API(&(asn->addr), &(api->addr));
	asn_INTEGER_to_int64(&(asn->chunkSize), &(api->chunk_size));

	asn_INTEGER_to_int64(&(asn->versionNscfg), &(api->versions.nscfg));
	asn_INTEGER_to_int64(&(asn->versionEvtcfg), &(api->versions.evtcfg));
	asn_INTEGER_to_int64(&(asn->versionSrvcfg), &(api->versions.srvcfg));

	/* broken and snapshot counters not yet managed */
	api->versions.snapshot = api->versions.broken = 0LL;

	if ( NULL != asn->storagePolicy ) {
		if (!list_conversion(asn->storagePolicy, &(api->storage_policy), key_value_pairs_convert_to_map))
			return FALSE;
	}

	if ( NULL != asn->dataSecurity ) {
		if (!list_conversion(asn->dataSecurity, &(api->data_security), key_value_pairs_convert_to_map))
			return FALSE;
	}

	if ( NULL != asn->dataTreatments ) {
		if (!list_conversion(asn->dataTreatments, &(api->data_treatments), key_value_pairs_convert_to_map))
			return FALSE;
	}

	if (NULL != asn->storageClass) {
		if (!list_conversion(asn->storageClass, &(api->storage_class), key_value_pairs_convert_to_map))
			return FALSE;
	}

	return TRUE;

}

static gboolean
hashtable_conversion(
		GHashTable *ht,
		struct NamespaceInfoValueList *nsinfo_vlist,
		GSList* (*conv_func)(GHashTable * ht, gboolean do_copy, GError **err))
{
	GSList* result = NULL, *p = NULL;
	GError *error = NULL;

	result = (conv_func(ht, TRUE, &error));
	if (result == NULL && error != NULL) {
		ERROR("Failed to convert map to key_value_pairs in namespace_info API to ASN conversion : %s",
				gerror_get_message(error));
		g_clear_error(&error);
		return FALSE;
	}

	if (result != NULL) {
		/* fill the array */
		for (p = result; p != NULL; p = p->next) {
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
namespace_info_API2ASN(const namespace_info_t * api, gint64 vers, NamespaceInfo_t * asn)
{
	if (!api || !asn)
		return FALSE;

	if (api->options && !hashtable_conversion(api->options, &(asn->options), key_value_pairs_convert_from_map))
		return FALSE;

	OCTET_STRING_fromBuf(&(asn->name), api->name, MIN(strlen(api->name), LIMIT_LENGTH_NSNAME));
	addr_info_API2ASN(&(api->addr), &(asn->addr));
	asn_int64_to_INTEGER(&(asn->chunkSize), api->chunk_size);

	asn_int64_to_INTEGER(&(asn->versionEvtcfg), api->versions.evtcfg);
	asn_int64_to_INTEGER(&(asn->versionSrvcfg), api->versions.srvcfg);
	asn_int64_to_INTEGER(&(asn->versionNscfg), api->versions.nscfg);
	/* marshall this namespace info part only for recent comm */
	if(vers >= 17) {
		TRACE("vers >= 17");
		if ( NULL != api->storage_policy) {
			asn->storagePolicy = g_malloc0(sizeof(struct NamespaceInfoValueList));
			if(!hashtable_conversion(api->storage_policy,
						asn->storagePolicy,
						key_value_pairs_convert_from_map))
				return FALSE;
		}

		if ( NULL != api->data_security) {
			asn->dataSecurity = g_malloc0(sizeof(struct NamespaceInfoValueList));
			if(!hashtable_conversion(api->data_security, 
						asn->dataSecurity, 
						key_value_pairs_convert_from_map))
				return FALSE;
		}

		if ( NULL != api->data_treatments ) {
			asn->dataTreatments = g_malloc0(sizeof(struct NamespaceInfoValueList));
			if(!hashtable_conversion(api->data_treatments,
						asn->dataTreatments,
						key_value_pairs_convert_from_map))
				return FALSE;
		}

		if(vers >= 18) {
			if ( NULL != api->storage_class ) {
				asn->storageClass = g_malloc0(sizeof(struct NamespaceInfoValueList));
				if(!hashtable_conversion(api->storage_class,
							asn->storageClass,
							key_value_pairs_convert_from_map))
					return FALSE;
			}
		}
	} else {
		TRACE("vers %"G_GINT64_FORMAT" < 17", vers);
	}

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
	if (NULL != asn->storagePolicy)
		asn->storagePolicy->list.free = parameter_cleanASN;
	if (NULL != asn->dataSecurity)
		asn->dataSecurity->list.free = parameter_cleanASN;
	if (NULL != asn->dataTreatments)
		asn->dataTreatments->list.free = parameter_cleanASN;
	if (NULL != asn->storageClass)
		asn->storageClass->list.free = parameter_cleanASN;

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NamespaceInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_NamespaceInfo, asn);

	errno = 0;
}

