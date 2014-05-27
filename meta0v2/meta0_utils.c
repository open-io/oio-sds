#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "meta0.utils"
#endif

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "./internals.h"
#include "./meta0_utils.h"

static void
garray_free(GArray *a)
{
	if (!a)
		return;
	g_array_free(a, TRUE);
}

/* ------------------------------------------------------------------------- */

guint16
meta0_utils_bytes_to_prefix(const guint8 *bytes)
{
	return *((guint16*)bytes);
}

GTree*
meta0_utils_array_to_tree(GPtrArray *byprefix)
{
	GTree *result = NULL;
	guint i, max;

	EXTRA_ASSERT(byprefix != NULL);
	result = meta0_utils_tree_create();

	for (i=0, max=byprefix->len; i<max ;i++) {
		guint16 prefix = i;
		gchar **v = byprefix->pdata[i];
		if (!v)
			continue;
		for (; *v ;v++)
			meta0_utils_tree_add_url(result, (guint8*)(&prefix), *v);
	}

	return result;
}

gboolean
meta0_utils_check_url_from_base(gchar **url) {
	gchar *colon;

	if ( ! url )
		return FALSE;
	gchar *end = *url + strlen(*url);

	if (! g_ascii_isdigit(*end)) {
		/* Find the ':' separator */
        	for (colon=end; colon>=*url && *colon != ':';colon--);
        	if (colon<=*url || colon>=(end-1) || *colon!=':') {
			return FALSE;
		}

		colon++;
		for (;colon<=end;colon++) {
			if (! g_ascii_isdigit(*colon)) {
				*colon='\0';
				break;
			}
		}
	}

	return TRUE;
}

GTree*
meta0_utils_list_to_tree(GSList *list)
{
	GSList *l;
	GTree *result = NULL;

	EXTRA_ASSERT(list != NULL);

	result = g_tree_new_full(
			hashstr_quick_cmpdata, NULL,
			g_free, (GDestroyNotify)garray_free);

	for (l=list; l ;l=l->next) {
		struct meta0_info_s *m0i;

		if (!(m0i = l->data))
			continue;

		gchar url[128];
		url[0] = '\0';
		grid_addrinfo_to_string(&(m0i->addr), url, sizeof(url));

		gsize len = m0i->prefixes_size;
		len = len / 2;
		GArray *pfx = g_array_new(FALSE, FALSE, sizeof(guint16));
		g_array_append_vals(pfx, m0i->prefixes, len);

		g_tree_replace(result, hashstr_create(url), pfx);
	}
	
	return result;
}

void
meta0_utils_array_add(GPtrArray *gpa, const guint8 *bytes, const gchar *s)
{
	guint len;
	gchar **v0, **v1;
	guint16 prefix;

	prefix = meta0_utils_bytes_to_prefix(bytes);

	if (!(v0 = gpa->pdata[prefix])) {
		len = 0;
		v1 = g_malloc0(sizeof(gchar*) * 2);
	} else {
		len = g_strv_length(v0);
		v1 = g_realloc(v0, sizeof(gchar*) * (len+2));
	}
	v1[len] = g_strdup(s);
	v1[len+1] = NULL;
	gpa->pdata[prefix] = v1;
}

gboolean
meta0_utils_array_replace(GPtrArray *gpa, const guint8 *bytes, const gchar *s, const gchar *d)
{
	guint i, len;
	gchar **v0;
	guint16 prefix;

	prefix = meta0_utils_bytes_to_prefix(bytes);

	if(!(v0 = gpa->pdata[prefix]))
		return FALSE;

	len = g_strv_length(v0);

	for( i=0; i < len ; i++) {
		if ( g_ascii_strncasecmp(v0[i],s, strlen(s))== 0 ) {
			g_free(v0[i]);
			v0[i]=g_strdup(d);
			return TRUE;
		}
	}
	return FALSE;
}

GPtrArray*
meta0_utils_list_to_array(GSList *list)
{
	GSList *l;
	GPtrArray *result = NULL;

	EXTRA_ASSERT(list != NULL);

	result = meta0_utils_array_create();

	for (l=list; l ;l=l->next) {
		gchar url[128];
		guint16 *p, *max;
		struct meta0_info_s *m0i;

		if (!(m0i = l->data))
			continue;

		memset(url, 0, sizeof(url));
		grid_addrinfo_to_string(&(m0i->addr), url, sizeof(url));

		p = (guint16*) m0i->prefixes;
		max = (guint16*) (m0i->prefixes + m0i->prefixes_size);
		for (; p<max; p++)
			meta0_utils_array_add(result, (guint8*)p, url);
	}

	return result;
}

GSList*
meta0_utils_tree_to_list(GTree *byurl)
{
	gboolean _traverser(gpointer k, gpointer v, gpointer u) {
		struct meta0_info_s *m0i;
		hashstr_t *hurl = k;
		GArray *pfx = v;
		GSList **pl = u;

		m0i = g_malloc0(sizeof(*m0i));
		grid_string_to_addrinfo(hashstr_str(hurl), NULL, &(m0i->addr));
		m0i->prefixes_size = 2 * pfx->len;
		m0i->prefixes = g_memdup(pfx->data, m0i->prefixes_size);
		*pl = g_slist_prepend(*pl, m0i);

		return FALSE;
	}

	GSList *result = NULL;

	EXTRA_ASSERT(byurl != NULL);
	g_tree_foreach(byurl, _traverser, &result);
	return result;
}

GSList*
meta0_utils_array_to_list(GPtrArray *array)
{
	GTree *tree;
	GSList *list;

	EXTRA_ASSERT(array != NULL);

	tree = meta0_utils_array_to_tree(array);
	list = meta0_utils_tree_to_list(tree);
	g_tree_destroy(tree);
	return list;
}

void
meta0_utils_array_clean(GPtrArray *array)
{
	guint i;

	if (!array)
		return;

	for (i=0; i<array->len ;i++) {
		gpointer p = array->pdata[i];
		if (p)
			g_strfreev((gchar**)p);
		array->pdata[i] = NULL;
	}
	g_ptr_array_free(array, TRUE);
}

gchar **
meta0_utils_array_get_urlv(GPtrArray *array, const guint8 *bytes)
{
	gchar **v;

	EXTRA_ASSERT(array != NULL);
	EXTRA_ASSERT(array->len == 65536);
	v = array->pdata[meta0_utils_bytes_to_prefix(bytes)];
	return v ? g_strdupv(v) : NULL;
}

void
meta0_utils_list_clean(GSList *list)
{
	g_slist_free_full(list, (GDestroyNotify)meta0_info_clean);
}

GPtrArray *
meta0_utils_array_create(void)
{
	guint i;
	GPtrArray *array;

	array = g_ptr_array_sized_new(65536);
	for (i=0; i<65536 ;i++)
		g_ptr_array_add(array, NULL);
	return array;
}

GPtrArray*
meta0_utils_array_dup(GPtrArray *in)
{
	register guint i, max;
	gchar **v;
	GPtrArray *result;

	result = g_ptr_array_sized_new(in->len);
	for (i=0,max=in->len; i<max ;i++) {
		if (!(v = in->pdata[i])) {
			g_ptr_array_add(result, NULL);
		} else {
			g_ptr_array_add(result, g_strdupv(v));
		}
	}
	return result;
}

GTree*
meta0_utils_tree_create(void)
{
	return g_tree_new_full(hashstr_quick_cmpdata, NULL,
			g_free, (GDestroyNotify)garray_free);
}

GTree*
meta0_utils_tree_add_url(GTree *tree, const guint8 *b, const gchar *url)
{
	GArray *prefixes;
	hashstr_t *hu;

	HASHSTR_ALLOCA(hu, url);
	prefixes = g_tree_lookup(tree, hu);
	if (!prefixes) {
		prefixes = g_array_new(FALSE, FALSE, 2);
		g_tree_replace(tree, hashstr_dup(hu), prefixes);
	}
	g_array_append_vals(prefixes, b, 1);

	return tree;
}


/* ------------------------------------------------------------------------- */

void
meta0_utils_array_meta1ref_clean(GPtrArray *array)
{
        guint i;

        if (!array)
                return;

        for (i=0; i<array->len ;i++) {
                gpointer p = array->pdata[i];
                if (p) {
                        g_free((gchar*)p);
		}
        }
        g_ptr_array_free(array, TRUE);
}

GPtrArray*
meta0_utils_array_meta1ref_dup(GPtrArray *in)
{
        register guint i, max;
        gchar *v;
        GPtrArray *result;

        result = g_ptr_array_sized_new(in->len);
        for (i=0,max=in->len; i<max ;i++) {
                if (!(v = in->pdata[i]))
                        continue;
                g_ptr_array_add(result, g_strdup(v));
        }
        return result;
}



gchar *
meta0_utils_pack_meta1ref(gchar *addr, gchar *ref, gchar *nb)
{
	gchar * result=NULL;
        result = g_strjoin("|",addr,ref,nb,NULL);
	return result;
}

gboolean
meta0_utils_unpack_meta1ref(const gchar *s_m1ref, gchar **addr, gchar **ref, gchar **nb)
{
	(void)addr ;(void) ref; (void) nb;
	gchar** split_result = g_strsplit(s_m1ref,"|",-1);
	if ( g_strv_length(split_result) != 3 )
        	return FALSE;

	*addr=strdup(split_result[0]);
	*ref=strdup(split_result[1]);
	*nb=strdup(split_result[2]);

	g_strfreev(split_result);
	return TRUE;

}


/* ------------------------------------------------------------------------- */
static gboolean
_is_usable_meta0(addr_info_t *m0addr, GSList *exclude) {
        GSList *l = NULL;
        for (l = exclude; l && l->data; l=l->next) {
                if(addr_info_equal(l->data, m0addr))
                        return FALSE;
        }
        return TRUE;
}

addr_info_t *
meta0_utils_getMeta0addr(gchar *namespace, GSList **m0_lst, GSList *exclude)
{
	addr_info_t *a = NULL;
	if (*m0_lst  == NULL) {
		GError *err = NULL;
		*m0_lst = list_namespace_services2(namespace,NAME_SRVTYPE_META0, &err);
		if (err) {
			GRID_WARN("Failed to get Meta0 addresses to namespace %s: (%d) %s",
					namespace, err->code, err->message);
			g_clear_error(&err);
			return NULL;
		}
	}
	GSList *m0;
	for (m0 = *m0_lst; m0 && m0->data; m0=m0->next) {
		service_info_t *srv = m0->data;
		if (_is_usable_meta0(&(srv->addr),exclude))
			a=&(srv->addr);
	}
	return a;
}

