#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.resolv.metacd"
#endif

#include "./gs_internals.h"

int resolver_metacd_is_up (struct metacd_s *m)
{
	char *path;
	struct stat stats;

	if (!m) {
		ERROR("invalid parameter");
		return 0;
	}
	
	path = m->path;
	
	if (!*(path)) {
		WARN("invalid path");
		return 0;
	}
	
	if (!stat(path, &stats)) {
		if (S_IFSOCK & stats.st_mode) {
			DEBUG ("%s ok", path);
			return 1;
		} else {
			WARN("%s present but not a socket", path);
			return 0;
		}
	}
	TRACE("METAcd unreachable through %s (%s)", path, strerror(errno));
	return 0;
}


void resolver_metacd_decache (struct metacd_s *m, const container_id_t cID)
{
	GError *err=NULL;
	struct metacd_connection_info_s mi;

	if (!m || !cID) {
		ERROR("Invalid parameter");
		return;
	}

	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	if (!metacd_remote_decache(&mi,cID,&err)) {
		DEBUG("cannot decache the container reference in the METACD (through %s)", m->path);
	}

	if (err) g_clear_error(&err);
}


void resolver_metacd_decache_all (struct metacd_s *m)
{
	GError *err=NULL;
	struct metacd_connection_info_s mi;

	if (!m) {
		ERROR("Invalid parameter");
		return;
	}

	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	if (!metacd_remote_decache_all(&mi,&err)) {
		DEBUG("cannot decache the container reference in the METACD (through %s)", m->path);
	}

	if (err) g_clear_error(&err);
}


GSList* resolver_metacd_get_meta2 (struct metacd_s *m, const container_id_t cID,
	GError **err)
{
	GSList *m2L=NULL;
	struct metacd_connection_info_s mi;
	
	if (!m || !cID) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}

	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	m2L = metacd_remote_get_meta2(&mi, cID, err);
	if (!m2L) {
		if (!err || !(*err))
			GSETERROR(err,"cannot resolve META2 with METACD");
		return NULL;
	}

	return m2L;
}

addr_info_t*
resolver_metacd_get_meta0 (struct metacd_s *m, GError **err)
{
	addr_info_t *m0Addr=NULL;
	GSList *m0L=NULL;
	struct metacd_connection_info_s mi;
	
	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	m0L = metacd_remote_get_meta0(&mi, err);
	if (!m0L) {
		GSETERROR(err,"cannot resolve META0 with METACD (invalid result)");
		return NULL;
	}
	
	if (!m0L->data) {
		g_slist_foreach (m0L, addr_info_gclean, NULL);
		g_slist_free (m0L);
		GSETERROR(err,"cannot resolve META0 with METACD (invalid result)");
		return NULL;
	}

	m0Addr = g_memdup(m0L->data, sizeof(addr_info_t));
	g_slist_foreach (m0L, addr_info_gclean, NULL);
	g_slist_free (m0L);

	if (!m0Addr) {
		GSETERROR(err,"memory allocation failure");
		return NULL;
	}

	return m0Addr;
}


addr_info_t* resolver_metacd_get_meta1 (struct metacd_s *m, const container_id_t cID,
	int ro, GSList *exclude, gboolean *p_ref_exists, GError **err)
{
	addr_info_t *m1Addr=NULL;
	GSList *m1L=NULL;
	struct metacd_connection_info_s mi;
	
	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	m1L = metacd_remote_get_meta1(&mi, cID, ro, p_ref_exists, exclude, err);
	if (!m1L) {
		GSETERROR(err,"cannot resolve META1 with METACD (invalid result)");
		return NULL;
	}
	if (! m1L->data) {
		g_slist_foreach (m1L, addr_info_gclean, NULL);
		g_slist_free (m1L);
		GSETERROR(err,"cannot resolve META1 with METACD (invalid result)");
		return NULL;
	}

	m1Addr = g_memdup(m1L->data, sizeof(addr_info_t));
	g_slist_foreach (m1L, addr_info_gclean, NULL);
	g_slist_free (m1L);

	if (!m1Addr) {
		GSETERROR(err,"memory allocation failure");
		return NULL;
	}
	
	return m1Addr;
}

int resolver_metacd_set_meta1_master(struct metacd_s *m, const container_id_t cid, const char *m1, GError **e)
{
	struct metacd_connection_info_s mi;
	
	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	if(!metacd_remote_set_meta1_master(&mi, cid, m1, e))
		return 0;
	return 1;
}

gboolean
resolver_metacd_put_content (struct metacd_s *m, struct meta2_raw_content_s *raw_content, GError **err)
{
	gboolean rc;
	struct metacd_connection_info_s mi;
	
	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	rc = metacd_remote_save_content(&mi, raw_content, err);
	if (!rc) {
		GSETERROR(err, "not cached");
		return FALSE;
	}

	return rc;
}

struct meta2_raw_content_s*
resolver_metacd_get_content (struct metacd_s *m, const container_id_t cID, const gchar *content, GError **err)
{
	struct meta2_raw_content_s *raw_content;
	struct metacd_connection_info_s mi;
	
	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	raw_content = metacd_remote_get_content(&mi, cID, content, err);
	if (!raw_content) {
		GSETERROR(err, "not found with metacd");
		return NULL;
	}

	return raw_content;
}

gboolean
resolver_metacd_del_content(struct metacd_s *m, const container_id_t cID, const gchar *path, GError **err)
{
	gboolean result = FALSE;
	struct metacd_connection_info_s mi;

	memset(&mi,0x00,sizeof(mi));
	memcpy(&(mi.metacd), m, sizeof(struct metacd_s));

	result = metacd_remote_forget_content(&mi, cID, path, err);
	if (!result) {
		GSETERROR(err, "not deleted");
		return FALSE;
	}

	return result;
}

void
resolver_metacd_free (struct metacd_s *m)
{
	if (m)
		g_free(m);
}


struct metacd_s* resolver_metacd_create (const char * const config, GError **err)
{
	char *metacdSock=NULL;
	struct metacd_s *m;

	if (!config || !*config)
	{
		GSETERROR(err,"Invalid parameter");
		return NULL;
	}

	DEBUG("Creating a METAcd resolver for %s", config);
	
	m = g_try_malloc0(sizeof(struct metacd_s));
	if (!m) {
		GSETERROR(err,"Memory allocation failure");
		return NULL;
	}

	memset (m->path,   0x00, sizeof(m->path));
	memset (m->nsName, 0x00, sizeof(m->nsName));
	m->timeout.op = 10000;
	m->timeout.cnx = 5000;

	metacdSock = getenv(GS_ENVKEY_METACDSOCK);
	if (!metacdSock) metacdSock = GS_DEFAULT_METACDSOCK;

	g_strlcpy (m->path, metacdSock, sizeof(m->path));
	g_strlcpy (m->nsName, config, sizeof(m->nsName));

	DEBUG("METACD using sock=%s namespace=%s timeout[cnx:%d op:%d]"
		" (you may overload the sock with environment key %s)",
		m->path, m->nsName,
		m->timeout.cnx, m->timeout.op,
		GS_ENVKEY_METACDSOCK);

	return m;
}

