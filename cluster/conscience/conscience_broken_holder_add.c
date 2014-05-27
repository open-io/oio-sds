#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "conscience.api.brk"
#endif
#include <stdlib.h>
#include <string.h>
#include "./conscience.h"
#include "./conscience_srvtype.h"
#include "./conscience_broken_holder_common.h"
#include "./conscience_broken_holder.h"

static gboolean remove_container(gpointer key, gpointer value, gpointer user_data);

/* ------------------------------------------------------------------------- */

static void
free_broken_content(gpointer p)
{
	memset(p, 'A', sizeof(struct broken_content_s));
	g_free(p);
}

gboolean
remove_container(gpointer key, gpointer value, gpointer user_data)
{
	struct broken_content_s *brk_content;
	gchar *str_cid;

	if (!value || !user_data) {
		ALERT("Invalid HT entry (%p %p %p)", key, value, user_data);
		return FALSE;
	}

	str_cid = user_data;
	brk_content = value;

	return 0 == g_ascii_strncasecmp(brk_content->container_id, str_cid, sizeof(brk_content->container_id));
}


static struct broken_meta1_s *
create_broken_meta1(addr_info_t * addr)
{
	gsize writen_size;
	struct broken_meta1_s *brk_m1;

	brk_m1 = g_try_malloc0(sizeof(struct broken_meta1_s));
	if (!brk_m1) {
		abort();
		return NULL;
	}

	writen_size = g_strlcpy(brk_m1->string, "META1:",
	    sizeof(brk_m1->string));
	addr_info_to_string(&(brk_m1->addr),
	    brk_m1->string + writen_size,
	    sizeof(brk_m1->string) - writen_size);

	if (addr)
		memcpy(&(brk_m1->addr), addr, sizeof(addr_info_t));
	return brk_m1;
}

static struct broken_meta2_s *
create_broken_meta2(addr_info_t * addr)
{
	struct broken_meta2_s *brk_m2;
	brk_m2 = g_try_malloc0(sizeof(struct broken_meta2_s));
	if (!brk_m2)
		abort();
	brk_m2->counter = 0;
	brk_m2->totally_broken = FALSE;
	brk_m2->last_alert_stamp = time(0);
	brk_m2->broken_containers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_broken_content);
	if (addr)
		memcpy(&(brk_m2->addr), addr, sizeof(addr_info_t));
	return brk_m2;
}

static struct broken_content_s *
create_broken_content(struct conscience_s *conscience, const gchar * cid, const gchar * path, const gchar * cause)
{
	struct conscience_srvtype_s *srvtype;
	struct broken_content_s *brk_content;

	brk_content = g_try_malloc0(sizeof(struct broken_content_s));
	if (!brk_content)
		abort();

	g_strlcpy(brk_content->container_id, cid, sizeof(brk_content->container_id));
	if (path) {
		g_strlcpy(brk_content->content_path, path, sizeof(brk_content->content_path));
		if (cause)
			g_strlcpy(brk_content->cause, cause, sizeof(brk_content->cause));
	}

	srvtype = conscience_get_locked_srvtype(conscience, NULL, "rawx", MODE_STRICT, 'r');
	if (srvtype) {
		brk_content->counter = conscience_srvtype_count_srv(srvtype, FALSE);
		conscience_release_locked_srvtype(srvtype);
	}

	return brk_content;
}

/* ------------------------------------------------------------------------- */

void
free_broken_m2(gpointer p)
{
	struct broken_meta2_s *brk_m2;

	if (!p)
		return;
	brk_m2 = p;

	if (brk_m2->broken_containers)
		g_hash_table_destroy(brk_m2->broken_containers);

	g_free(brk_m2);
}

static void
break_meta2(struct broken_meta2_s *brk_m2, struct conscience_s *conscience)
{
	if (!brk_m2)
		return;
	if (brk_m2->totally_broken)
		return;
	brk_m2->totally_broken = TRUE;
	g_hash_table_remove_all(brk_m2->broken_containers);
	do {
		struct conscience_srvtype_s *srvtype;
		srvtype = conscience_get_locked_srvtype(conscience, NULL, "rawx", MODE_STRICT, 'r');
		if (srvtype) {
			brk_m2->counter = conscience_srvtype_count_srv(srvtype, FALSE);
			conscience_release_locked_srvtype(srvtype);
		}
	} while (0);
}

void
broken_holder_add_meta1(struct broken_holder_s * bh, struct broken_fields_s * bf)
{
	GError *error_local;
	broken_meta1_t *brk_meta1;
	addr_info_t *addr;

	error_local = NULL;
	addr = build_addr_info(bf->ip, bf->port, &error_local);
	if (!addr) {
		WARN("Failed to break the META1 : %s", gerror_get_message(error_local));
		if (error_local)
			g_error_free(error_local);
		return ;
	}

	if (!g_hash_table_lookup(bh->ht_meta1, addr)) {

		brk_meta1 = create_broken_meta1(addr);

		do {
			struct conscience_srvtype_s *srvtype;
			srvtype = conscience_get_locked_srvtype(bh->conscience, NULL, "meta2", MODE_STRICT, 'r');
			if (srvtype) {
				brk_meta1->counter = conscience_srvtype_count_srv(srvtype, FALSE);
				conscience_release_locked_srvtype(srvtype);
			}
		} while (0);

		g_hash_table_insert(bh->ht_meta1, &(brk_meta1->addr), brk_meta1);
		INFO("META1 broken [%s:%d]", bf->ip, bf->port);
	}
	else
		DEBUG("META1 yet broken [%s:%d]", bf->ip, bf->port);

	g_free(addr);
}

static void
broken_holder_add_container(struct broken_holder_s * bh,
    struct broken_meta2_s * brk_m2, struct broken_fields_s * bf)
{
	struct broken_content_s *brk_content;
	char key[STRLEN_CONTAINERID + LIMIT_LENGTH_CONTENTPATH + 8];

	/*First lookup the container*/
	g_snprintf(key, sizeof(key), "%s:all", bf->cid);
	if (g_hash_table_lookup(brk_m2->broken_containers, key)) {
		DEBUG("Container already broken [%s:%d/%s]", bf->ip, bf->port, bf->cid);
		return ;
	}

	if (bf->content) {
		g_snprintf(key, sizeof(key), "%s:%s", bf->cid, bf->content);
		brk_content = g_hash_table_lookup(brk_m2->broken_containers, key);
		if (brk_content) {
			DEBUG("Content yet broken [%s:%d/%s/%s]", bf->ip, bf->port, bf->cid, bf->content);
			return ;
		}
		brk_content = create_broken_content(bh->conscience, bf->cid, bf->content, bf->cause);
	} else {
		/*remove all the content entries */
		g_hash_table_foreach_remove(brk_m2->broken_containers, remove_container, bf->cid);
		brk_content = create_broken_content(bh->conscience, bf->cid, NULL, NULL);
	}

	g_hash_table_insert(brk_m2->broken_containers, g_strdup(key), brk_content);
	
	DEBUG("Container now broken [%s:%d/%s(%s(/%s))]", bf->ip, bf->port,
		brk_content->container_id, brk_content->content_path, brk_content->cause);
}

void
broken_holder_add_in_meta2(struct broken_holder_s * bh, struct broken_fields_s * bf)
{
	GError *error_local;
	addr_info_t m2_addr;
	struct broken_meta2_s *brk_m2;

	error_local = NULL;
	do {
		addr_info_t *wrk_addr = build_addr_info( bf->ip, bf->port, &error_local);
		if (!wrk_addr) {
			WARN("Invalid META2 address [%s:%d] : %s", bf->ip, bf->port, gerror_get_message(error_local));
			if (error_local)
				g_error_free(error_local);
			return;
		}
		memcpy(&m2_addr,wrk_addr,sizeof(addr_info_t));
		g_free(wrk_addr);
	} while (0);

	/*find the broken META2 */
	brk_m2 = g_hash_table_lookup(bh->ht_meta2, &m2_addr);
	if (!brk_m2) {
		brk_m2 = create_broken_meta2(&m2_addr);
		g_hash_table_insert(bh->ht_meta2, &(brk_m2->addr), brk_m2);
		DEBUG("META2 [%s:%d] ready [%s]", bf->ip, bf->port, bf->cid);
	}
	if (brk_m2->totally_broken) {
		DEBUG("META2 broken [%s:%d], element not saved [%s]", bf->ip, bf->port, bf->cid);
		return ;
	}

	if (!bf->cid) {
		break_meta2(brk_m2, bh->conscience);
	} else {
		broken_holder_add_container(bh, brk_m2, bf);
	}
}

void
broken_holder_add_element(struct broken_holder_s * bh, const gchar * element)
{
	gchar **tokens;
	gsize tokens_length;
	struct broken_fields_s bf;

	if (!bh || !element) {
		WARN("Invalid parameter");
		return ;
	}

	memset(&bf,0x00,sizeof(bf));
	bf.packed = element;
	bf.ns = bh->conscience->ns_info.name;

	tokens = g_strsplit(element,":",0);
	if (!tokens) {
		WARN("Invalid format");
		return;
	}
	tokens_length = g_strv_length(tokens);
	
	/*special case for the broken META1 */
	if (tokens_length == 3 && g_ascii_strcasecmp(tokens[0],"META1")) {
		bf.ip = tokens[1];
		bf.port = atoi(tokens[2]);
		broken_holder_add_meta1(bh, &bf);
	}
	else if (tokens_length>=2 && tokens_length<=5) {
		bf.ip = tokens[0];
		bf.port = atoi(tokens[1]);
		switch (tokens_length) {
		case 5:
			bf.cause = *(tokens[4]) ? tokens[4] : NULL;
		case 4:
			bf.content = *(tokens[3]) ? tokens[3] : NULL;
		case 3:
			bf.cid = *(tokens[2]) ? tokens[2] : NULL;
		case 2:
			broken_holder_add_in_meta2(bh, &bf);
			break;
		}
	}
	else {
		WARN("Invalid broken element : [%s]", element);
	}
	
	g_strfreev(tokens);
}

