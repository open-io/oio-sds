#define MODULE_NAME "metacd"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN MODULE_NAME".plugin"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <meta0v2/meta0_remote.h>
#include <meta1v2/meta1_remote.h>
#include <meta2/remote/meta2_remote.h>
#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>

#include "../lib/meta_resolver_explicit.h"

#include "./limited_cache.h"
#include "./locktab.h"
#include "./metacd_module.h"

#define MSG_BAD_REQUEST "Bad request"
#define MSG_INTERNAL_ERROR "Internal error"

#define JUMPERR(CTX,C,M) do {\
	reply_context_clear((CTX), FALSE);\
	reply_context_set_message ((CTX),\
		((CTX)->warning && (CTX)->warning->code ? (CTX)->warning->code : (C)),\
		((CTX)->warning && (CTX)->warning->message ? (CTX)->warning->message : (M)));\
	goto errorLabel;\
} while (0)

#define EXTRACT_CONTENT_PATH(req_ctx,ctx,wrkName) do {\
	void *field=NULL;\
	gsize fieldLen=0;\
	if (!message_get_field (req_ctx->request, MSGKEY_PATH, sizeof(MSGKEY_PATH)-1, &field, &fieldLen, &(ctx.warning)))\
	{\
		GSETCODE(&(ctx.warning), 400, "Bad Request (no path)");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	}\
	if (!field || fieldLen<=0 || fieldLen>((sizeof(wrkName))-1))\
	{\
		GSETCODE(&(ctx.warning), 400, "Bad Request (invalid path)");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	}\
	else { memset(wrkName,0x00,sizeof(wrkName)); memcpy (wrkName, field, fieldLen); }\
} while (0)

#define EXTRACT_CONTAINER_ID(req_ctx,ctx,cid,str_cid) do {\
	void *field=NULL;\
	gsize fieldLen=0;\
	if (!message_get_field (req_ctx->request, MSGKEY_CID, sizeof(MSGKEY_CID)-1, &field, &fieldLen, &(ctx.warning)))\
	{\
		GSETCODE(&(ctx.warning), 400, "Bad Request (no container id)");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	} if (!field || fieldLen!=sizeof(container_id_t)) {\
		GSETCODE(&(ctx.warning), 400, "Bad Request (invalid container id)");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	} else {\
		memset(cid, 0x00, sizeof(container_id_t));\
		memcpy(cid, field, sizeof(container_id_t));\
		(void)container_id_to_string (cid, str_cid, sizeof(str_cid)-1);\
	}\
} while (0)

#define EXTRACT_NAMESPACE_NAME(req_ctx,ctx,wrkName) do {\
	void *field=NULL;\
	gsize fieldLen=0;\
	if (!message_get_field (req_ctx->request, MSGKEY_NS, sizeof(MSGKEY_NS)-1, &field, &fieldLen, &(ctx.warning)))\
	{\
		GSETCODE(&(ctx.warning), 400, "Bad Request (no namespace name)");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	}\
	if (!field || fieldLen<=0 || fieldLen>((sizeof(wrkName))-1))\
	{\
		GSETCODE(&(ctx.warning), 400, "Bad Request (invalid namespace name)");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	}\
	else { memset(wrkName,0x00,sizeof(wrkName)); memcpy (wrkName, field, fieldLen); }\
} while (0)

#define EXTRACT_BODY(req_ctx,ctx,gba_result,minLen,maxLen) do {\
	void *field=NULL; gsize fieldLen=0;\
	if (!message_get_BODY (req_ctx->request, &field, &fieldLen, &(ctx.warning))) {\
		GSETCODE(&(ctx.warning), 400,"No body in the message");\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	} else if (!field || fieldLen<(minLen) || fieldLen>(maxLen)) {\
		GSETCODE(&(ctx.warning), 400, "Invalid  size (should be between %d and %d)", (minLen), (maxLen));\
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);\
	} else {\
		gba_result = g_byte_array_append(g_byte_array_new(), field, fieldLen);\
	}\
} while (0)

#define RESOLVERS_LOCK()   do { TRACE("LOCKING(main)"); g_static_rec_mutex_lock (&resolvers_mutex); } while (0)
#define RESOLVERS_UNLOCK() do { TRACE("UNLOCKING(main)"); g_static_rec_mutex_unlock (&resolvers_mutex); } while (0)
#define LOG_ACCESS(CTX,FMT,...) do { if (flag_access) reply_context_log_access((CTX), FMT, __VA_ARGS__); } while (0)

/* ------------------------------------------------------------------------- */

struct namespace_cache_s {
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	resolver_direct_t *m0;
	limited_cache_t *m1;
	limited_cache_t *chunks_cache;
	locktab *chunks_locks;
};

struct chunk_key_s {
	container_id_t cid;
	gchar *content_path;
};

static struct {
	gint cnx;
	gint req;
} cs_timeout = {500,10000};

static int flag_access = 0;
static gssize meta1_cache_size = 100000;
static time_t meta1_cache_expiration = 86400;/* 24h */

static gboolean chunks_cache_noatime = TRUE;
static gssize chunks_cache_size = 50000;
static time_t chunks_cache_expiration = 86400;/* 24h */

static GStaticRecMutex resolvers_mutex;
static GHashTable *caches = NULL;

/* ------------------------------------------------------------------------- */

static guint
chunk_key_hash(gconstpointer k)
{
	const struct chunk_key_s *key = k;
	guint32 h = djb_hash_buf(key->cid, sizeof(container_id_t));

	return djb_hash_buf3(h, (guint8 *) (key->content_path), strlen_len(
			(guint8 *) (key->content_path), LIMIT_LENGTH_CONTENTPATH));
}

static gboolean
chunk_key_equal(gconstpointer k1, gconstpointer k2)
{
	const struct chunk_key_s *key1;
	const struct chunk_key_s *key2;

	key1 = k1;
	key2 = k2;
	return (k1 == k2) ||
		(!memcmp(key1->cid, key2->cid, sizeof(container_id_t))
		 && !g_strcmp0(key1->content_path, key2->content_path));
}

static gpointer
chunk_key_copy(gconstpointer k)
{
	struct chunk_key_s *copy;
	const struct chunk_key_s *key;
	if (!k)
		return NULL;
	key = k;
	copy = g_memdup(key, sizeof(struct chunk_key_s));
	copy->content_path = g_strndup(key->content_path, LIMIT_LENGTH_CONTENTPATH);
	return copy;
}

static void
chunk_key_free(gpointer k)
{
	struct chunk_key_s *key = k;
	if (!k)
		return;
	if (key->content_path)
		g_free(key->content_path);
	g_free(key);
}


static gpointer
cid_copy(gconstpointer p)
{
	if (!p)
		return NULL;
	return g_memdup(p, sizeof(container_id_t));
}

static gpointer
addrinfo_copy(gconstpointer p)
{
	if (!p)
		return NULL;
	return g_memdup(p, sizeof(addr_info_t));
}

static void
free_cache(gpointer r)
{
	struct namespace_cache_s *nsCache = NULL;

	if (r) {
		nsCache = (struct namespace_cache_s *) r;
		if (nsCache->m0)
			resolver_direct_free(nsCache->m0);
		if (nsCache->m1)
			limited_cache_destroy(nsCache->m1);
		if (nsCache->chunks_cache)
			limited_cache_destroy(nsCache->chunks_cache);
		if (nsCache->chunks_locks)
			locktab_fini(nsCache->chunks_locks);
	}
}

static struct namespace_cache_s *
namespace_cache_init(const char *name, GError ** err)
{
	static struct limited_cache_callbacks cid_callbacks = {
		container_id_hash,
		container_id_equal,
		g_free,
		cid_copy,
		g_free,
		addrinfo_copy
	};

	static struct limited_cache_callbacks chunks_callbacks = {
		chunk_key_hash,
		chunk_key_equal,
		chunk_key_free,
		chunk_key_copy,
		metautils_gba_clean,
		(value_copier_f)metautils_gba_dup
	};

	struct namespace_cache_s *nsCache = NULL;

	DEBUG("Get/Create a namespace cache for %s", name);

	nsCache = g_hash_table_lookup(caches, name);
	if (nsCache)
		DEBUG("Namespace cache found for %s, no init pahse needed", name);
	else {
		struct locktab_ctx_s callbacks;

		nsCache = (struct namespace_cache_s *) g_try_malloc0(sizeof(struct namespace_cache_s));
		if (!nsCache) {
			GSETERROR(err, "Memory allocation failure");
			ALERT("Memory allocation failure");
			return NULL;
		}

		/*read the configuration file*/
		g_strlcpy(nsCache->ns_name, name, sizeof(nsCache->ns_name)-1);

		nsCache->m0 = resolver_direct_create2(name, cs_timeout.cnx, cs_timeout.req, err);
		if (!nsCache->m0) {
			GSETERROR(err, "Direct resolver init failed");
			return NULL;
		}

		nsCache->m1 = limited_cache_create(meta1_cache_size, meta1_cache_expiration,
				&cid_callbacks, 0, err);
		if (!nsCache->m1) {
			GSETERROR(err, "META1 cache init failed");
			return NULL;
		}

		nsCache->chunks_cache = limited_cache_create(chunks_cache_size, chunks_cache_expiration,
				&chunks_callbacks, (chunks_cache_noatime ? LCFLAG_NOATIME : 0), err);
		if (!nsCache->chunks_cache) {
			GSETERROR(err, "CHUNKS cache init failed");
			return NULL;
		}

		callbacks.ctx_data = NULL;
		callbacks.on_destroy = NULL;
		callbacks.copy_key = chunk_key_copy;
		callbacks.hash_key = chunk_key_hash;
		callbacks.equal_key = chunk_key_equal;
		callbacks.free_key = chunk_key_free;
		nsCache->chunks_locks = g_try_malloc(locktab_get_struct_size());
		locktab_init(nsCache->chunks_locks, 4, &callbacks);

		g_hash_table_insert (caches, g_strdup(name), nsCache);
	}

	return nsCache;
}


/* ------------------------------------------------------------------------- */


static gboolean
reply_addr_info_list(struct reply_context_s *ctx, GSList * aL)
{
	GSList *list_of_lists, *cursor;

	reply_context_clear(ctx, TRUE);

	list_of_lists = gslist_split(aL, 64);
	for (cursor = list_of_lists; cursor; cursor = cursor->next) {
		void *bufAI = NULL;
		gsize bufAISize = 0;
		GSList *nextList;

		nextList = (GSList *) cursor->data;

		if (!addr_info_marshall(nextList, &bufAI, &bufAISize, &(ctx->warning))) {
			GSETERROR(&(ctx->warning), "Cannot marshall the address list");
			JUMPERR(ctx, 500, ctx->warning->message);
		}

		if (cursor->next)
			reply_context_set_message(ctx, 206, "Partial content");
		else
			reply_context_set_message(ctx, 200, "OK");

		reply_context_set_body(ctx, bufAI, bufAISize, REPLYCTX_DESTROY_ON_CLEAN);
		reply_context_reply(ctx, &(ctx->warning));
	}

	reply_context_clear(ctx, FALSE);
	gslist_chunks_destroy(list_of_lists, NULL);
	return 1;
      errorLabel:
	gslist_chunks_destroy(list_of_lists, NULL);
	return 0;
}

static GSList*
_locate_meta2(struct namespace_cache_s *nsCache, const gchar *ns, container_id_t cid, const gchar *str_cid, GError **err)
{
	addr_info_t *m2_ai = NULL;
	GSList *m2L = NULL;

	/* get the information from the META1 cache */
	m2_ai = (addr_info_t *) limited_cache_get(nsCache->m1, cid);
	if (m2_ai) {
		DEBUG("Successfully resolved META2 from cache NS=[%s] ID=[%s]", nsCache->ns_name, str_cid);
		return g_slist_prepend(NULL, m2_ai);
	}

	m2L = resolver_direct_get_meta2(nsCache->m0, ns, cid, err, 2);
	if (!m2L) {
		if (err != NULL)
			g_prefix_error(err, "Cannot explicitely resolve META2 for NS=[%s] ID=[%s]: ",
					nsCache->ns_name, str_cid);
		else
			GSETERROR(err, "Cannot explicitely resolve META2 for NS=[%s] ID=[%s]",
					nsCache->ns_name, str_cid);
		return NULL;
	}
	if (!(m2L->data)) {
		g_slist_foreach(m2L, addr_info_gclean, NULL);
		g_slist_free(m2L);
		GSETERROR(err, "Cannot explicitely resolve META2 (invalid return) for NS=[%s] ID=[%s]",
			nsCache->ns_name, str_cid);
		return NULL;
	}

	DEBUG("Successfully resolved META2 from META1 for NS=[%s] ID=[%s]", nsCache->ns_name, str_cid);
	limited_cache_put(nsCache->m1, cid, m2L->data);
	return m2L;
}

static GByteArray*
_stat_content(const gchar *ns, container_id_t cid, gchar *str_cid, gchar *path, GError **err)
{
	GSList *l, *list_of_addr = NULL;
	GByteArray *gba_content = NULL;
	struct namespace_cache_s *nsCache=NULL;
	gchar content_path[LIMIT_LENGTH_CONTENTPATH];
	struct chunk_key_s key;
	struct meta2_raw_content_s *raw_content;

	memset(&key, 0x00, sizeof(key));
	memset(content_path, 0x00, sizeof(content_path));

        memcpy(key.cid, cid, sizeof(container_id_t));
	g_strlcpy(content_path, path, sizeof(content_path)-1);
	key.content_path = content_path;

	/* Ensure the namespace is cached, then lock the content */
	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (ns, err);
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETCODE(err, 500, "Namespace unknown NS=[%s]", ns);
		return NULL;
	}
	if (!locktab_lock(nsCache->chunks_locks, &key)) {
		GSETCODE(err, 500, "Lock failure", ns);
		return NULL;
	}

	/* check the cache's content */
	gba_content = limited_cache_get(nsCache->chunks_cache, &key);
	if (gba_content) {
		locktab_unlock(nsCache->chunks_locks, &key);
		DEBUG("Content cached");
		return gba_content;
	}

	/* locate the meta2 with the "hint" provided by the client */
	if (!(list_of_addr = _locate_meta2(nsCache, ns, cid, str_cid, err))) {
		locktab_unlock(nsCache->chunks_locks, &key);
		GSETCODE(err, CODE_CONTAINER_NOTFOUND, "Container not found");
		return NULL;
	}

	/* Not found in the cache, then we call all the META2 returned
	 * by the meta2 localization, and we keep the first positive
	 * result*/
	for (raw_content=NULL, l=list_of_addr; l && !raw_content ;l=l->next) {
		raw_content = NULL;

		struct metacnx_ctx_s cnx;
		metacnx_clear(&cnx);
		metacnx_init_with_addr(&cnx, (addr_info_t*) l->data, err);
		raw_content = meta2raw_remote_get_chunks(&cnx, err, cid, key.content_path, strlen(key.content_path));
		metacnx_close(&cnx);
		metacnx_clear(&cnx);
	}
	g_slist_foreach(list_of_addr, addr_info_gclean, NULL);
	g_slist_free(list_of_addr);
	list_of_addr = NULL;

	if (!raw_content) {
		locktab_unlock(nsCache->chunks_locks, &key);
		GSETERROR(err, "Content not found");
		return NULL;
	}
	else {
		gba_content = meta2_maintenance_marshall_content(raw_content, err);
		meta2_maintenance_destroy_content(raw_content);
		raw_content = NULL;
	}

	if (!gba_content) {
		locktab_unlock(nsCache->chunks_locks, &key);
		GSETCODE(err, 500, "serialization error");
		return NULL;
	}

	/*insert in the cache*/
	limited_cache_put(nsCache->chunks_cache, &key, gba_content);
	locktab_unlock(nsCache->chunks_locks, &key);
	return gba_content;
}


/* ------------------------------------------------------------------------- */


static gboolean
handler_get_meta0 (struct request_context_s *req_ctx)
{
	struct namespace_cache_s *nsCache=NULL;
	addr_info_t *m0_ai=NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];

	/*initiations*/
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;

	EXTRACT_NAMESPACE_NAME(req_ctx,ctx,nsName);

	DEBUG("Trying to resolve META0 for NS=[%s]", nsName);

	/*start caching this namespace*/
	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	m0_ai = nsCache ? g_memdup(&(nsCache->m0->meta0), sizeof(addr_info_t)) : NULL;
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETERROR(&(ctx.warning),"Namespace unknown NS=[%s]", nsName);
		JUMPERR(&ctx,500,MSG_INTERNAL_ERROR);
	}
	if (!m0_ai) {
		GSETCODE(&(ctx.warning), 500, "Memory allocation failure");
		JUMPERR(&ctx,500,MSG_INTERNAL_ERROR);
	}
	
	do { /*reply the address saquence*/
		GSList aL = {NULL,NULL};
		aL.data = m0_ai;
		reply_addr_info_list (&ctx, &aL);
	} while (0);

	g_free(m0_ai);
	LOG_ACCESS(&ctx, "/%.*s", (int)sizeof(nsName), nsName);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	if (m0_ai)
		g_free(m0_ai);
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	LOG_ACCESS(&ctx, "/%.*s", (int)sizeof(nsName), nsName);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}


static gboolean
handler_get_meta1(struct request_context_s *req_ctx)
{
	struct namespace_cache_s *nsCache=NULL;
	addr_info_t *m1_ai=NULL;
	GSList *exclude = NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];
	container_id_t cid;
	gchar str_cid [STRLEN_CONTAINERID+1];
	GError *e = NULL;
	gboolean ro = FALSE, ref_exists = FALSE;

	/*initiations*/
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;

	EXTRACT_CONTAINER_ID(req_ctx,ctx,cid,str_cid);
	EXTRACT_NAMESPACE_NAME(req_ctx,ctx,nsName);
	message_extract_flag(req_ctx->request, "RO", FALSE, &ro);
	e = message_extract_body_encoded(req_ctx->request, &exclude, addr_info_unmarshall);
	if( NULL != e ) {
		if(!g_str_has_prefix(e->message, "Missing body"))
			DEBUG("Error while unmarshalling body : %s", e->message);
		g_clear_error(&e);
	}

	DEBUG("Trying to resolve META1 for NS=[%s] ID=[%s]", nsName, str_cid);

	/*start caching this namespace*/
	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETERROR(&(ctx.warning),"Namespace unknown NS=[%s]", nsName);
		JUMPERR(&ctx,500,MSG_INTERNAL_ERROR);
	}

	/* TODO : gba_content contains the excluded services and must be used */

	m1_ai = resolver_direct_get_meta1(nsCache->m0, cid, ro, exclude, &(ctx.warning));
	if (!m1_ai) {
		JUMPERR(&ctx, 500, MSG_INTERNAL_ERROR);
	}

	ref_exists = limited_cache_has(nsCache->m1, cid, NULL);
	if (!ref_exists) {
		limited_cache_put(nsCache->m1, cid, NULL);
		DEBUG("Created META1 reference for NS=[%s] ID=[%s] master=[]", nsName, str_cid);
	} else {
		DEBUG("META1 reference already exists for NS=[%s] ID=[%s]", nsName, str_cid);
	}

	do {/*reply the address sequence*/
		GSList aL = {NULL,NULL};
		aL.data = m1_ai;
		void *bufAI = NULL;
		gsize bufAISize = 0;
		if (!addr_info_marshall(&aL, &bufAI, &bufAISize, &(ctx.warning))) {
			GSETERROR(&(ctx.warning), "Cannot marshall the address list");
			JUMPERR(&ctx, 500, ctx.warning->message);
		}
		reply_context_set_message(&ctx, 200, "OK");
		reply_context_set_body(&ctx, bufAI, bufAISize, REPLYCTX_DESTROY_ON_CLEAN);
		reply_context_add_strheader_in_reply(&ctx, "REF_EXISTS", ref_exists ? "TRUE" : "FALSE");
		reply_context_reply(&ctx, &(ctx.warning));
	} while (0);

	g_free(m1_ai);
	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	if (m1_ai)
		g_free(m1_ai);
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}

static gboolean
handler_set_m1_master(struct request_context_s *req_ctx)
{
	struct namespace_cache_s *nsCache=NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];
	container_id_t cid;
	gchar str_cid [STRLEN_CONTAINERID+1];
	char master[128];

	/*initiations*/
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;

	memset(nsName,0x00,sizeof(nsName));
	memset(str_cid,0x00,sizeof(str_cid));

	EXTRACT_NAMESPACE_NAME(req_ctx,ctx,nsName);
	EXTRACT_CONTAINER_ID(req_ctx, ctx, cid, str_cid);
	ctx.warning = message_extract_string(req_ctx->request, NAME_MSGKEY_M1_MASTER, master, sizeof(master));
	if(NULL != ctx.warning)
		JUMPERR(&ctx, 400, MSG_BAD_REQUEST);
	
	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETERROR(&(ctx.warning),"Cannot get the cache for namespace=%s", nsName);
		ERROR("%s", ctx.warning->message);
	} else {
		resolver_direct_set_meta1_master(nsCache->m0, cid, master, &(ctx.warning));
	}

	reply_context_set_message (&ctx, 200, "OK");
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, &(ctx.warning));

	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);

	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;
}


static gboolean
handler_get_meta2(struct request_context_s *req_ctx)
{
	struct namespace_cache_s *nsCache=NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];
	container_id_t cid;
	gchar str_cid [STRLEN_CONTAINERID+1];

	GSList *aL=NULL;

	/*initiations*/
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;

	memset(nsName,0x00,sizeof(nsName));
	memset(str_cid,0x00,sizeof(str_cid));

	EXTRACT_CONTAINER_ID(req_ctx,ctx,cid,str_cid);
	EXTRACT_NAMESPACE_NAME(req_ctx,ctx,nsName);

	DEBUG("Trying to resolve META2 for NS=[%s] ID=[%s]", nsName, str_cid);

	RESOLVERS_LOCK();
	nsCache = namespace_cache_init(nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETERROR(&(ctx.warning), "Cannot init a namespace cache");
		JUMPERR(&ctx, 500, MSG_INTERNAL_ERROR);
	}

	aL = _locate_meta2(nsCache, nsName, cid, str_cid, &(ctx.warning));
	if (!aL) {
		GSETERROR(&(ctx.warning), "Container not found");
		JUMPERR(&ctx, 500, MSG_INTERNAL_ERROR);
	}

	reply_addr_info_list(&ctx, aL);
	g_slist_foreach (aL, addr_info_gclean, NULL);
	g_slist_free(aL);
	aL = NULL;

	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	if (aL)
		g_slist_free(aL);
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;
}


static gboolean
handler_decache(struct request_context_s *req_ctx)
{
	struct namespace_cache_s *nsCache=NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];
	gboolean cid_present=TRUE;
	container_id_t cid;
	gchar str_cid [STRLEN_CONTAINERID+1];

	/*initiations*/
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;

	memset(nsName,0x00,sizeof(nsName));
	memset(str_cid,0x00,sizeof(str_cid));

	EXTRACT_NAMESPACE_NAME(req_ctx,ctx,nsName);

	do {
		void *field=NULL;
		gsize fieldLen=0;
		if (!message_get_field (req_ctx->request, MSGKEY_CID, sizeof(MSGKEY_CID)-1,
				&field, &fieldLen, &(ctx.warning))) {
			cid_present = FALSE;
		}
		if (!field || fieldLen!=sizeof(container_id_t)) {
			GSETCODE(&(ctx.warning), 400, "Bad Request (invalid container id)");
			JUMPERR(&ctx, 400, MSG_BAD_REQUEST);
		} else {
			memset(&cid, 0x00, sizeof(container_id_t));
			memcpy(&cid, field, sizeof(container_id_t));
			(void)container_id_to_string (cid, str_cid, sizeof(str_cid)-1);
		}
	} while (0);
	
	/*start caching this namespace*/

	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETERROR(&(ctx.warning),"Cannot get the cache for namespace=%s", nsName);
		ERROR("%s", ctx.warning->message);
	} else {
		if (cid_present) {
			INFO("Decaching NS=[%s] ID=[%s]", nsName, str_cid);
			limited_cache_del (nsCache->m1, cid);
		} else {
			INFO("Decaching NS=[%s] ID=[any]", nsName);
			resolver_direct_decache_all (nsCache->m0);
		}
	}

	reply_context_set_message (&ctx, 200, "OK");
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, &(ctx.warning));

	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);

	LOG_ACCESS(&ctx, "/%.*s/%.*s", (int)sizeof(nsName), nsName, (int)sizeof(str_cid), str_cid);
	reply_context_clear (&ctx, TRUE);
	return TRUE;
}

static gboolean
handler_chunks_get(struct request_context_s *req_ctx)
{
	/*declarations*/
	struct reply_context_s ctx;
	GByteArray *gba_content = NULL;

	struct {
		gchar ns[LIMIT_LENGTH_NSNAME];
		gchar path[LIMIT_LENGTH_CONTENTPATH];
		container_id_t cid;
		gchar str_cid[STRLEN_CONTAINERID];
	} args;

	/*initiations*/
	memset(&args, 0x00, sizeof(args));
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;

	EXTRACT_NAMESPACE_NAME(req_ctx, ctx, args.ns);
	EXTRACT_CONTAINER_ID(req_ctx, ctx, args.cid, args.str_cid);
	EXTRACT_CONTENT_PATH(req_ctx, ctx, args.path);
	
	DEBUG_DOMAIN("chunks","get(%s/%s/%s)", args.ns, args.str_cid, args.path);
	
	gba_content = _stat_content(args.ns, args.cid, args.str_cid, args.path, &(ctx.warning));
	if (!gba_content) {
		GSETERROR(&(ctx.warning), "Content not found");
		goto errorLabel;
	}
		
	/* reply the success */	
	reply_context_clear(&ctx, FALSE);
	reply_context_set_message(&ctx, 200, "chunks found");
	reply_context_set_body(&ctx, gba_content->data, gba_content->len, REPLYCTX_DESTROY_ON_CLEAN);
	reply_context_reply(&ctx, &(ctx.warning));
	g_byte_array_free(gba_content, FALSE);

	LOG_ACCESS(&ctx, "/%.*s/%.*s/%.*s",
		(int)sizeof(args.ns), args.ns,
		(int)sizeof(args.str_cid), args.str_cid,
		(int)sizeof(args.path), args.path);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	if (ctx.warning)
		reply_context_set_message(&ctx, ctx.warning->code, ctx.warning->message);
	else 
		reply_context_set_message(&ctx, 500, "Content not found");
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	LOG_ACCESS(&ctx, "/%.*s/%.*s/%.*s",
		(int)sizeof(args.ns), args.ns,
		(int)sizeof(args.str_cid), args.str_cid,
		(int)sizeof(args.path), args.path);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}

static gboolean
handler_chunks_save(struct request_context_s *req_ctx)
{
	struct namespace_cache_s *nsCache=NULL;
	gssize cache_size;
	struct reply_context_s ctx;
	GByteArray *gba_content = NULL;
	char nsName[LIMIT_LENGTH_NSNAME];
	gchar str_cid[STRLEN_CONTAINERID + 1];
	gchar content_path[LIMIT_LENGTH_CONTENTPATH + 1];
	struct chunk_key_s key;

	/*initiations*/
	memset(str_cid, 0x00, sizeof(str_cid));
	memset(&key, 0x00, sizeof(key));
	memset(content_path, 0x00, sizeof(content_path));
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;
	key.content_path = content_path;

	EXTRACT_BODY(req_ctx, ctx, gba_content, 1, 100*sizeof(chunk_info_t));
	EXTRACT_NAMESPACE_NAME(req_ctx, ctx,nsName);
	EXTRACT_CONTAINER_ID(req_ctx, ctx, key.cid, str_cid);
	EXTRACT_CONTENT_PATH(req_ctx, ctx, content_path);

	DEBUG_DOMAIN("chunks", "put(%s/%s/%s) size=%u", nsName, str_cid, key.content_path, gba_content->len);

	/* start caching this namespace */
	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETCODE(&(ctx.warning), 500, "Namespace unknown NS=[%s]", nsName);
		JUMPERR(&ctx, 500, "Namespace not found");
	}

	if (locktab_lock(nsCache->chunks_locks, &key)) {
		limited_cache_put(nsCache->chunks_cache, &key, gba_content);
		locktab_unlock(nsCache->chunks_locks, &key);
	}
	cache_size = limited_cache_get_size(nsCache->chunks_cache);

	reply_context_clear(&ctx, FALSE);
	reply_context_set_message(&ctx, 200, "Content now cached");
	reply_context_set_body(&ctx, NULL, 0, 0);
	reply_context_reply(&ctx, NULL);
	
	/*reply the address saquence*/

	g_byte_array_free(gba_content, TRUE);
	LOG_ACCESS(&ctx, "cache=%d;/%.*s/%.*s/%.*s",
		cache_size,
		(int)sizeof(nsName), nsName,
		(int)sizeof(str_cid), str_cid,
		(int)sizeof(key.content_path), key.content_path);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	if (gba_content)
		g_byte_array_free(gba_content, TRUE);
	
	LOG_ACCESS(&ctx, "/%.*s/%.*s/%.*s",
		(int)sizeof(nsName), nsName,
		(int)sizeof(str_cid), str_cid,
		(int)sizeof(key.content_path), key.content_path);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}

static gboolean
handler_chunks_forget(struct request_context_s *req_ctx)
{
	gssize cache_size;
	struct namespace_cache_s *nsCache=NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];
	gchar str_cid[STRLEN_CONTAINERID + 1];
	gchar content_path[LIMIT_LENGTH_NSNAME + 1];
	struct chunk_key_s key;

	/*initiations*/
	memset(str_cid, 0x00, sizeof(str_cid));
	memset(&key, 0x00, sizeof(key));
	memset(content_path, 0x00, sizeof(content_path));
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;
	key.content_path = content_path;

	EXTRACT_NAMESPACE_NAME(req_ctx, ctx,nsName);
	EXTRACT_CONTAINER_ID(req_ctx, ctx,key.cid, str_cid);
	EXTRACT_CONTENT_PATH(req_ctx, ctx, content_path);

	DEBUG_DOMAIN("chunks","del(%s/%s/%s)", nsName, str_cid, key.content_path);

	/*start caching this namespace*/
	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETCODE(&(ctx.warning), 500, "Namespace unknown NS=[%s]", nsName);
		JUMPERR(&ctx, 500, "Namespace not found");
	}
	if (locktab_lock(nsCache->chunks_locks, &key)) {
		limited_cache_del(nsCache->chunks_cache, &key);
		locktab_unlock(nsCache->chunks_locks, &key);
	}
	cache_size = limited_cache_get_size(nsCache->chunks_cache);

	reply_context_clear(&ctx, FALSE);
	reply_context_set_message(&ctx, 200, "Content not cached anymore");
	reply_context_set_body(&ctx, NULL, 0, 0);
	reply_context_reply(&ctx, NULL);
	
	LOG_ACCESS(&ctx, "cache=%d;/%.*s/%.*s/%.*s",
		cache_size,
		(int)sizeof(nsName), nsName,
		(int)sizeof(str_cid), str_cid,
		(int)sizeof(key.content_path), key.content_path);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	LOG_ACCESS(&ctx, "/%.*s/%.*s/%.*s",
		(int)sizeof(nsName), nsName,
		(int)sizeof(str_cid), str_cid,
		(int)sizeof(key.content_path), key.content_path);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}


static gboolean
handler_chunks_flush(struct request_context_s *req_ctx)
{
	gssize cache_size;
	struct namespace_cache_s *nsCache=NULL;
	struct reply_context_s ctx;
	char nsName[LIMIT_LENGTH_NSNAME];

	/*initiations*/
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;
	EXTRACT_NAMESPACE_NAME(req_ctx, ctx, nsName);

	DEBUG_DOMAIN("chunks", "Flushing the chunks for NS=[%s]", nsName);

	RESOLVERS_LOCK();
	nsCache = namespace_cache_init (nsName, &(ctx.warning));
	RESOLVERS_UNLOCK();
	if (!nsCache) {
		GSETCODE(&(ctx.warning), 500, "Namespace unknown NS=[%s]", nsName);
		JUMPERR(&ctx, 500, "Namespace not found");
	}
	limited_cache_flush(nsCache->chunks_cache);
	cache_size = limited_cache_get_size(nsCache->chunks_cache);

	reply_context_clear(&ctx, FALSE);
	reply_context_set_message(&ctx, 200, "DONE");
	reply_context_set_body(&ctx, NULL, 0, 0);
	reply_context_reply(&ctx, NULL);

	LOG_ACCESS(&ctx, "cache=%d;NS=%.*s", cache_size, (int)sizeof(nsName), nsName);
	reply_context_clear (&ctx, TRUE);
	return TRUE;

errorLabel:
	reply_context_set_body (&ctx, NULL, 0, 0);
	reply_context_reply (&ctx, NULL);
	LOG_ACCESS(&ctx, "NS=%.*s", (int)sizeof(nsName), nsName);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}


/* ------------------------------------------------------------------------- */


typedef gboolean(*_cmd_handler_f) (struct request_context_s *);


static _cmd_handler_f
__find_handler(gchar * n, gsize l)
{
	struct cmd_s *c;
	static struct cmd_s { char *c; _cmd_handler_f h; } CMD[] = {
		{ MSGNAME_METACD_GETM0,           handler_get_meta0     },
		{ MSGNAME_METACD_GETM1,           handler_get_meta1     },
		{ MSGNAME_METACD_GETM2,           handler_get_meta2     },
		{ MSGNAME_METACD_DECACHE,         handler_decache       },

		{ MSGNAME_METACD_V1_CHUNKS_FLUSH, handler_chunks_flush  },
		{ MSGNAME_METACD_V1_CHUNKS_DEL,   handler_chunks_forget },

		{ MSGNAME_METACD_V2_CHUNKS_PUT,   handler_chunks_save   },
		{ MSGNAME_METACD_V2_CHUNKS_FLUSH, handler_chunks_flush  },
		{ MSGNAME_METACD_V2_CHUNKS_GET,   handler_chunks_get    },
		{ MSGNAME_METACD_V2_CHUNKS_DEL,   handler_chunks_forget },
		/**/
		{ MSGNAME_METACD_SET_M1_MASTER,   handler_set_m1_master },
		{ NULL, NULL}
	};

	(void) l;
	for (c = CMD; c && c->c; c++) {
		if (0 == g_ascii_strcasecmp(c->c, n))
			return c->h;
	}
	return NULL;
}


static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
	void *name = NULL;
	gsize nameLen = 0;

	(void) param;
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	if (!message_has_NAME(m, err))
		return 0;

	message_get_NAME(m, &name, &nameLen, err);
	if (!name || nameLen <= 0) {
		INFO("The message contains an invalid NAME parameter");
		return 0;
	}

	return (__find_handler((gchar *) name, nameLen) != NULL ? 1 : 0);
}


static gint
plugin_handler(MESSAGE m, gint cnx, void *param, GError ** err)
{
	void *name;
	gsize nameLen;
	_cmd_handler_f f;
	struct request_context_s ctx;

	(void) param;

	memset(&ctx, 0x00, sizeof(struct request_context_s));
	ctx.fd = cnx;
	ctx.request = m;

	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	message_get_NAME(m, &name, &nameLen, err);
	if (!name || nameLen <= 6) {
		GSETERROR(err, "The message contains an invalid NAME parameter");
		return 0;
	}

	if (!(f = __find_handler((gchar *) name, nameLen))) {
		GSETERROR(err, "This message does not concern this plugin.");
		return 0;
	}

	if (!f(&ctx)) {
		GSETERROR(err, "METACD could not manage this message");
		return 0;
	}
	return 1;
}

static gboolean
_read_param_bool(GHashTable *params, const gchar *key, gboolean def)
{
	return metautils_cfg_get_bool(g_hash_table_lookup(params, key), def);
}

static gint64
_read_param_i64(GHashTable *params, const gchar *key, gint64 def)
{
	gchar *str;
	gchar *endPtr=NULL;
	gint64 tmp_value;

	str = g_hash_table_lookup(params, key);
	if (!str)
		return def;

	tmp_value = g_ascii_strtoll (str, &endPtr, 10);
	if (tmp_value==0 && endPtr==str) {
		ERROR("bad configuration : %s must contain a positive integer (%s)",
				key, "unexpected characters");
		return def;
	}
	if ((tmp_value==G_MAXINT64 || tmp_value==G_MININT64) && errno==ERANGE) {
		ERROR("bad configuration : %s must contain a positive integer (%s)",
				key, "out of int64 range");
		return def;
	}
	return tmp_value;
}

#define CLAMP_IT(W,low,high) do { W=CLAMP(W,low,high); gint64 i64 = (W); NOTICE("[%s] set to [%"G_GINT64_FORMAT"]", #W, i64); } while (0)
#define DUMP_VAR_BOOL(W) do { NOTICE("[%s] set to [%s]", #W, (W ? "ON" : "OFF")); } while (0)

static gint
plugin_init(GHashTable * params, GError ** err)
{
	DEBUG("about to init METAcd");

	if (!params) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}
	if (caches) {
		GSETERROR(err, "internal caches already set : trying to init twice!");
		return 0;
	}

	g_static_rec_mutex_init(&resolvers_mutex);

	/*overrides the default meta1 cache value if present and valid */
	flag_access = _read_param_bool(params, KEY_PARAM_ACCESSLOG, FALSE);
	DUMP_VAR_BOOL(flag_access);

	meta1_cache_expiration = _read_param_i64(params, KEY_PARAM_META1CACHE_EXPIRATION, DEFAULT_META1CACHE_EXPIRATION);
	CLAMP_IT((meta1_cache_expiration), 1, 604800);
	
	chunks_cache_expiration = _read_param_i64(params, KEY_PARAM_CHUNKSCACHE_EXPIRATION, DEFAULT_CHUNKSCACHE_EXPIRATION);
	CLAMP_IT(chunks_cache_expiration, 1, 604800);
	
	meta1_cache_size = _read_param_i64(params, KEY_PARAM_META1CACHE_SIZE, DEFAULT_META1CACHE_SIZE);
	CLAMP_IT(meta1_cache_size, 1, 1000000);
	
	chunks_cache_size = _read_param_i64(params, KEY_PARAM_CHUNKSCACHE_SIZE, DEFAULT_CHUNKSCACHE_SIZE);
	CLAMP_IT(chunks_cache_size, 1, 100000);

        chunks_cache_noatime = _read_param_bool(params, KEY_PARAM_CHUNKSCACHE_NOATIME, TRUE);
	DUMP_VAR_BOOL(chunks_cache_noatime);

	cs_timeout.cnx = _read_param_i64(params, KEY_PARAM_CSTO_CNX, 1000);
	CLAMP_IT(cs_timeout.cnx, 100, 120000);

	cs_timeout.req = _read_param_i64(params, KEY_PARAM_CSTO_REQ, 4000);
	CLAMP_IT(cs_timeout.req, 100, 120000);

	/* Overrides the default Timeouts in the communications to the consciences */
	do {
		gchar *str;
		if (NULL != (str = g_hash_table_lookup(params, KEY_PARAM_CSTO_CNX))) {
			gchar *endPtr=NULL;
			gint64 i64 = g_ascii_strtoll (str, &endPtr, 10);
			cs_timeout.cnx = CLAMP(i64,100,60000);
		}
		if (NULL != (str = g_hash_table_lookup(params, KEY_PARAM_CSTO_REQ))) {
			gchar *endPtr=NULL;
			gint64 i64 = g_ascii_strtoll (str, &endPtr, 10);
			cs_timeout.req = CLAMP(i64,100,60000);
		}
		NOTICE("Conscience time-out set to [%d,%d]", cs_timeout.cnx, cs_timeout.req);
	} while (0);

	/*init the caches repository */
	caches = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_cache);
	if (!message_handler_add("metacd", plugin_matcher, plugin_handler, err)) {
		g_hash_table_destroy(caches);
		GSETERROR(err, "metacd module error : cannot register the plugin handler");
		return 0;
	}

	NOTICE("METAcd init done");
	return 1;
}


static gint
plugin_close(GError ** err)
{
	(void) err;
	DEBUG("about to clean METAcd");
	if (caches)
		g_hash_table_destroy(caches);
	INFO("METAcd init cleaned");
	return 1;
}


struct exported_api_s exported_symbol = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

