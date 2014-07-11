#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "rawx_config.h"


static void
_addr_rule_gclean(gpointer data, gpointer udata)
{
	(void) udata;
	addr_rule_g_free(data);
}

/**********************************************************************/

char *
_get_compression_algorithm(apr_pool_t *p, namespace_info_t *ns_info)
{
	apr_size_t s_len;
	GByteArray* algo;

	if (!ns_info || !ns_info->options)
		return apr_pstrdup(p, "ZLIB");

	algo = g_hash_table_lookup(ns_info->options, NS_COMPRESS_ALGO_OPTION);
	if (!algo)
		return apr_pstrdup(p, "ZLIB");

	s_len = algo->len;
	return apr_pstrndup(p, (char*)algo->data, s_len);
}

apr_int64_t
_get_compression_block_size(apr_pool_t *p, namespace_info_t *ns_info)
{
	GByteArray* bsize = NULL;
	gchar bsize_buff[256];
	int i_len;

	(void) p;
	if (!ns_info || !ns_info->options)
		return DEFAULT_STREAM_BUFF_SIZE;

	bsize = g_hash_table_lookup(ns_info->options, NS_COMPRESS_BLOCKSIZE_OPTION);
	if (!bsize)
		return DEFAULT_STREAM_BUFF_SIZE;

	i_len = bsize->len;
	bzero(bsize_buff, sizeof(bsize_buff));
	apr_snprintf(bsize_buff, sizeof(bsize_buff), "%.*s", i_len, ((char*)bsize->data));

	return g_ascii_strtoll(bsize_buff, NULL, 10);
}

GSList*
_get_acl(apr_pool_t *p, namespace_info_t *ns_info)
{
	GSList *acl = NULL;
	GByteArray* acl_allow, *acl_deny;
	
	if (!ns_info || !ns_info->options)
		return NULL;

	acl_allow = g_hash_table_lookup(ns_info->options, NS_ACL_ALLOW_OPTION);
	acl_deny = g_hash_table_lookup(ns_info->options, NS_ACL_DENY_OPTION);

	acl = g_slist_concat(parse_acl(acl_allow, TRUE), parse_acl(acl_deny, FALSE));
	if (!acl)
		return NULL;
		
	GSList *src, *dst;
	guint i, list_length;

	list_length = g_slist_length(acl);

	/* Copy the list content */
	dst = apr_pcalloc(p, sizeof(GSList) * list_length);
	if (list_length > 1) {
		for (i=0; i < list_length - 2; i++)
			dst[i].next = dst + i + 1;
	}

	/* copy the original data */
	for (i=0, src=acl; src ;src=src->next,i++) {
		if (src->data)
			dst[i].data = apr_pmemdup(p, src->data, sizeof(addr_rule_t));
	}

	g_slist_foreach(acl, _addr_rule_gclean, NULL);
	g_slist_free(acl);
	return dst;
}

gboolean
update_rawx_conf(apr_pool_t* p, rawx_conf_t **rawx_conf, const gchar* ns_name)
{
	rawx_conf_t* new_conf = NULL;
        namespace_info_t* ns_info;
        GError *local_error = NULL;

        ns_info = get_namespace_info(ns_name, &local_error);
        if (!ns_info)
                return FALSE;

	new_conf = apr_palloc(p, sizeof(rawx_conf_t));
	char * stgpol = NULL;
	stgpol = namespace_storage_policy(ns_info, ns_info->name);
	if(NULL != stgpol) {
		new_conf->sp = storage_policy_init(ns_info, stgpol);
	}

	new_conf->ni = ns_info;
	new_conf->acl = _get_acl(p, ns_info);
        new_conf->last_update = time(0);

	*rawx_conf = new_conf;
	return TRUE;
}

