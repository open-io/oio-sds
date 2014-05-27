#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "conscience.api.brk"
#endif
#include <string.h>
#include <errno.h>
#include "./conscience_broken_holder.h"
#include "./conscience_broken_holder_common.h"

struct broken_holder_s*
conscience_create_broken_holder ( struct conscience_s *conscience )
{
	struct broken_holder_s *bh;

	bh = g_try_malloc0(sizeof(struct broken_holder_s));
	if (!bh)
		return NULL;
	
	bh->conscience = conscience;
	bh->ht_meta2 = g_hash_table_new_full(addr_info_hash, addr_info_equal, NULL, free_broken_m2);
	bh->ht_meta1 = g_hash_table_new_full(addr_info_hash, addr_info_equal, NULL, g_free);
	
	if (!bh->ht_meta1 || !bh->ht_meta2) {
		conscience_destroy_broken_holder( bh );
		return NULL;
	}
	return bh;
}

void
conscience_destroy_broken_holder( struct broken_holder_s *bh )
{
	if (!bh)
		return;
	if (bh->ht_meta1)
		g_hash_table_destroy( bh->ht_meta1 );
	if (bh->ht_meta2)
		g_hash_table_destroy( bh->ht_meta2 );
	memset( bh, 0x00, sizeof(struct broken_holder_s) );
	g_free( bh );
}

static gboolean
broken_holder_run_meta1( struct broken_holder_s *bh, time_t oldest,
	gpointer udata, on_brk_meta1_f m1)
{
	gboolean done = FALSE;
	GHashTableIter iter;
	gpointer k, v;
	
	TRACE("Starting a run of the broken meta1.");

	g_hash_table_iter_init( &iter, bh->ht_meta1);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		struct broken_meta1_s *brk_m1 = v;
		if (brk_m1->date_insertion >= oldest) {
			if (!m1( udata, brk_m1 )) {
				return FALSE;
			}
			done = TRUE;
		}
	}
	if (done) {
		if (!m1(udata,NULL)) {
			return FALSE;
		}
	}

	TRACE("Broken META1 successfully ran.");
	return TRUE;
}

static gboolean
broken_holder_run_contents( struct broken_holder_s *bh, time_t oldest,
	gpointer udata, on_brk_content_f c)
{
	gboolean done = FALSE;
	GHashTableIter m2_iter, iter;
	gpointer k, v, m2_k, m2_v;
	struct broken_meta2_s *brk_m2;
	struct broken_content_s *brk_content;
	
	TRACE("Starting a run of the broken contents.");
	
	g_hash_table_iter_init( &iter, bh->ht_meta2);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		brk_m2 = v;
		if (brk_m2->totally_broken) {
			if (brk_m2->date_insertion >= oldest) {
				if (!c( udata, brk_m2, NULL )) {
					return FALSE;
				}
				done = TRUE;
			}
		}
		else if (g_hash_table_size(brk_m2->broken_containers) > 0) {
			g_hash_table_iter_init( &m2_iter, brk_m2->broken_containers );
			while (g_hash_table_iter_next(&m2_iter,&m2_k,&m2_v)) {
				brk_content = m2_v;
				if (brk_content->date_insertion >= oldest) {
					if (!c( udata, brk_m2, brk_content )) {
						return FALSE;
					}
					done = TRUE;
				}
			}
		}
	}
	if (done) {
		if (!c(udata,NULL,NULL)) {
			return FALSE;
		}
	}

	TRACE("Broken contents successfully ran.");
	return TRUE;
}

gboolean
broken_holder_run_elements( struct broken_holder_s *bh, time_t oldest,
	gpointer udata, on_brk_meta1_f m1, on_brk_content_f c)
{
	gboolean rc;
	
	if (!bh || (!m1 && !c)) {
		WARN("Invalid parameter (%p %p %p)", bh, m1, c);
		return FALSE;
	}

	rc = TRUE;
	if (m1)
		rc = broken_holder_run_meta1(bh,oldest,udata,m1);
	if (rc && c)
		rc = broken_holder_run_contents(bh,oldest,udata,c);
	return rc;
}

gchar*
broken_holder_write_meta1( struct broken_meta1_s *m1 )
{
	int s;
	char buffer[STRLEN_ADDRINFO+sizeof("META1:")+8];
	if (!m1)
		return g_strdup("***invalid element***");
	s = g_snprintf(buffer, sizeof(buffer), "META1:");
	s += addr_info_to_string(&(m1->addr), buffer+s, sizeof(buffer)-s);
	return g_strndup(buffer, sizeof(buffer));
}

gchar*
broken_holder_write_meta2( struct broken_meta2_s *m2 )
{
	int s;
	char buffer[STRLEN_ADDRINFO+16];
	if (!m2)
		return g_strdup("***invalid element***");
	s = addr_info_to_string(&(m2->addr), buffer, sizeof(buffer)-4);
	g_snprintf(buffer+s, sizeof(buffer)-s, ":::");
	return g_strndup(buffer, sizeof(buffer));
}

gchar*
broken_holder_write_content( struct broken_meta2_s *m2, struct broken_content_s *c )
{
	gsize s;
	gchar buffer[2048];

	if (!m2 || !c)
		return g_strdup("invalid element");
	
	s = addr_info_to_string(&(m2->addr), buffer, sizeof(buffer));
	
	if (c->content_path[0] && c->cause[0])
		g_snprintf(buffer+s,sizeof(buffer)-s,":%s:%s:%s", c->container_id, c->content_path, c->cause);
	else if (c->content_path[0])
		g_snprintf(buffer+s,sizeof(buffer)-s,":%s:%s:", c->container_id, c->content_path);
	else
		g_snprintf(buffer+s,sizeof(buffer)-s,":%s::", c->container_id);

	return g_strndup(buffer, sizeof(buffer));
}

void
broken_holder_flush( struct broken_holder_s *bh )
{
	if (!bh)
		return;
	if (bh->ht_meta1)
		g_hash_table_remove_all(bh->ht_meta1);
	if (bh->ht_meta2)
		g_hash_table_remove_all(bh->ht_meta2);
}

gboolean
broken_holder_check_element_format( struct broken_holder_s *bh,
	const gchar *element )
{
	gchar ** tokens;
	gboolean rc;
	gsize length;
	
	if (!bh || !element) {
		errno = EINVAL;
		return FALSE;
	}

	tokens = g_strsplit(element, ":", 0);
	if (!tokens) {
		errno = EBADMSG;
		return FALSE;
	}

	length = g_strv_length(tokens);
	if (length >=2 && length <=5) {
		errno = 0;
		rc = TRUE;
	} else {
		errno = EPROTO;
		rc = FALSE;
	}
	g_strfreev(tokens);
	
	return rc;
}

