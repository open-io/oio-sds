#include <unistd.h>

#include <glib.h>
#include <json.h>

#include "oio_core.h"

#define PREPEND(Result,List) do { \
	next = (List)->next; \
	List->next = (Result); \
	(Result) = List; \
	List = next; \
} while (0)

static GSList*
gslist_merge_random(GSList *l1, GSList *l2)
{
	GSList *next, *result = NULL;

	while (l1 || l2) {
		if (l1 && l2) {
			if (g_random_boolean())
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
		else {
			if (l1)
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
	}

	return result;
}

static void
gslist_split_in_two(GSList *src, GSList **r1, GSList **r2)
{
	GSList *next, *l1 = NULL, *l2 = NULL;

	while (src) {
		if (src)
			PREPEND(l1, src);
		if (src)
			PREPEND(l2, src);
	}

	*r1 = l1, *r2 = l2;
}

GSList *
oio_ext_gslist_shuffle(GSList *src)
{
	GSList *l1=NULL, *l2=NULL;

	gslist_split_in_two(src, &l1, &l2);
	return gslist_merge_random(
		(l1 && l1->next) ? oio_ext_gslist_shuffle(l1) : l1,
		(l2 && l2->next) ? oio_ext_gslist_shuffle(l2) : l2);
}

GError *
oio_ext_extract_json (struct json_object *obj,
		struct oio_ext_json_mapping_s *tab)
{
	g_assert (obj != NULL);
	g_assert (tab != NULL);
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++)
		*(p->out) = NULL;
	if (!json_object_is_type(obj, json_type_object))
		return NEWERROR(400, "Not an object");
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++) {
		struct json_object *o = NULL;
		if (!json_object_object_get_ex(obj, p->name, &o) || !o) {
			if (!p->mandatory)
				continue;
			return NEWERROR(400, "Missing field [%s]", p->name);
		}
		if (!json_object_is_type(o, p->type))
			return NEWERROR(400, "Invalid type for field [%s]", p->name);
		*(p->out) = o;
	}
	return NULL;
}

struct oio_thread_local_s
{
	gchar *reqid;
	GTree *pairs;
};

static void _otl_clean (gpointer p) {
	if (!p) return;
	struct oio_thread_local_s *otl = p;
	if (otl->reqid) {
		g_free(otl->reqid);
		otl->reqid = NULL;
	}
	if (otl->pairs) {
		g_tree_destroy (otl->pairs);
		otl->pairs = NULL;
	}
	g_free(otl);
}

static GPrivate th_local_key_reqid = G_PRIVATE_INIT(_otl_clean);

const char *
oio_local_get_reqid (void)
{
	struct oio_thread_local_s *otl = g_private_get(&th_local_key_reqid);
	return otl ? otl->reqid : NULL;
}

void
oio_local_set_reqid (const char *reqid)
{
	struct oio_thread_local_s *otl = g_private_get(&th_local_key_reqid);
	if (!otl) {
		otl = g_malloc0 (sizeof(*otl));
		g_private_replace (&th_local_key_reqid, otl);
	}
	oio_str_replace (&otl->reqid, reqid);
}

void
oio_local_set_random_reqid (void)
{
	struct {
		pid_t pid:16;
		guint8 buf[14];
	} bulk;
	bulk.pid = getpid();
	oio_str_randomize(bulk.buf, sizeof(bulk.buf));

	char hex[33];
	oio_str_bin2hex((guint8*)&bulk, sizeof(bulk), hex, sizeof(hex));
	oio_local_set_reqid(hex);
}

static int
_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored)
{
	(void) ignored;
	return g_strcmp0(a, b);
}

void
oio_local_set_value (const char *k, const char *v)
{
	struct oio_thread_local_s *otl = g_private_get(&th_local_key_reqid);
	if (!otl) {
		otl = g_malloc0 (sizeof(*otl));
		otl->pairs = g_tree_new_full (_strcmp3, NULL, g_free, g_free);
		g_private_replace (&th_local_key_reqid, otl);
	}
	g_tree_replace (otl->pairs, g_strdup(k), g_strdup(v));
}

const char*
oio_local_get_value (const char *k)
{
	struct oio_thread_local_s *otl = g_private_get(&th_local_key_reqid);
	if (!otl || !otl->pairs) return NULL;
	return g_tree_lookup(otl->pairs, k);
}

