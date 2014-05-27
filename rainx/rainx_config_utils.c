#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "rainx_config.h"
#include "rainx_internals.h"

#define RAINX_CONF_UPDATE_DELAY 10

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
update_rainx_conf_if_necessary(apr_pool_t* p, rawx_conf_t **rainx_conf)
{
	time_t now = time(0);
	if ((*rainx_conf)->last_update + RAINX_CONF_UPDATE_DELAY < now) {
		return update_rainx_conf(p, rainx_conf, (*rainx_conf)->ni->name);
	}
	return FALSE;
}

gboolean
update_rainx_conf(apr_pool_t* p, rawx_conf_t **rainx_conf, const gchar* ns_name)
{
	GError *local_error = NULL;
	namespace_info_t* ns_info = NULL;
	struct storage_policy_s *stgpol = NULL;
	GSList *acls = NULL;

	ns_info = get_namespace_info(ns_name, &local_error);
	if (!ns_info)
		return FALSE;

	char *polname = NULL;
	if(!(polname = namespace_storage_policy(ns_info, ns_info->name)))
		goto error_label;

	stgpol = storage_policy_init(ns_info, polname);
	g_free(polname);
	if (stgpol == NULL) {
		goto error_label;
	}

	// FIXME: free ACLs somewhere
	acls = _get_acl(p, ns_info);

	if (*rainx_conf != NULL) {
		/* ACLs are allocated with APR, we must prevent them from being
		 * cleaned by g_free. */
		(*rainx_conf)->acl = NULL;
		/* Do not free, just clean and reuse the memory */
		rawx_conf_clean(*rainx_conf);
	} else {
		/* Allocate on server's pool */
		*rainx_conf = apr_palloc(p, sizeof(rawx_conf_t));
	}

	/* Copy references that were allocated with glib */
	(*rainx_conf)->ni = ns_info;
	(*rainx_conf)->sp = stgpol;
	(*rainx_conf)->acl = acls;
	(*rainx_conf)->last_update = time(0);

	return TRUE;

error_label:
	if (ns_info != NULL) {
		namespace_info_free(ns_info);
	}
	if (stgpol != NULL) {
		storage_policy_clean(stgpol);
	}
	return FALSE;
}

