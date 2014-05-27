#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "conscience.api"
#endif
#include <stdlib.h>
#include <string.h>
#include "./conscience.h"
#include "./conscience_srvtype.h"
#include "./conscience_broken_holder_common.h"
#include "./conscience_broken_holder.h"

/* ------------------------------------------------------------------------- */

void
broken_holder_remove_meta2( struct broken_holder_s *bh, struct broken_fields_s *bf )
{
	char key [STRLEN_CONTAINERID+LIMIT_LENGTH_CONTENTPATH+1];
	memset(key, '\0', sizeof(key));
	g_snprintf(key, sizeof(key), "%s:%s", bf->cid, bf->content);
	g_hash_table_remove( bh->ht_meta2, key);
}

void
broken_holder_remove_meta1( struct broken_holder_s *bh, struct broken_fields_s *bf )
{
	char key [STRLEN_CONTAINERID+LIMIT_LENGTH_CONTENTPATH+1];
	memset(key, '\0', sizeof(key));
	g_snprintf(key, sizeof(key), "%s:%s", bf->cid, bf->content);
	g_hash_table_remove( bh->ht_meta1, key);
}

void
broken_holder_remove_content( struct broken_holder_s *bh, struct broken_fields_s *bf )
{
	GHashTableIter iter;
	gpointer k=NULL, v=NULL;
	char key [STRLEN_CONTAINERID+LIMIT_LENGTH_CONTENTPATH+1];

	memset(key, '\0', sizeof(key));
	g_snprintf(key, sizeof(key), "%s:%s", bf->cid, bf->content);

	/*remove it from all the META2*/
	g_hash_table_iter_init( &iter, bh->ht_meta2 );
	while (g_hash_table_iter_next(&iter,&k, &v)) {
		struct broken_meta2_s *brk_m2 = v;
		g_hash_table_remove( brk_m2->broken_containers, key);
	}
}

void
broken_holder_remove_container( struct broken_holder_s *bh, struct broken_fields_s *bf )
{
	GHashTableIter iter;
	gpointer k=NULL, v=NULL;
	char key [STRLEN_CONTAINERID+LIMIT_LENGTH_CONTENTPATH+1];

	memset(key, '\0', sizeof(key));
	g_snprintf(key, sizeof(key), "%s:all", bf->cid);

	/*remove it from all the META2*/
	g_hash_table_iter_init( &iter, bh->ht_meta2 );
	while (g_hash_table_iter_next(&iter,&k, &v)) {
		struct broken_meta2_s *brk_m2 = v;
		g_hash_table_remove( brk_m2->broken_containers, key);
	}
}

void
broken_holder_remove_element( struct broken_holder_s *bh, const gchar *element )
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

	DEBUG("Fixing broken element [%s]", element);

	tokens = g_strsplit(element,":",0);
	if (!tokens) {
		WARN("Invalid format");
		return;
	}
	tokens_length = g_strv_length(tokens);
	
	/*special case for the broken META1 */
	if (tokens_length == 3 && g_ascii_strcasecmp(tokens[0],"META1")) {
		TRACE("META1 matched");
		bf.ip = tokens[1];
		bf.port = atoi(tokens[2]);
		broken_holder_remove_meta1( bh, &bf );
	}
	else if (tokens_length == 2) {
		TRACE("META2 matched");
		bf.ip = tokens[0];
		bf.port = atoi(tokens[1]);
		broken_holder_remove_meta2( bh, &bf );
	}
	else if (tokens_length == 3) {
		TRACE("Container matched");
		bf.ip = tokens[0];
		bf.port = atoi(tokens[1]);
		bf.cid = *(tokens[2]) ? tokens[2] : NULL;
		broken_holder_remove_container( bh, &bf );
	}
	else if (tokens_length == 4) {
		TRACE("Container matched");
		bf.ip = tokens[0];
		bf.port = atoi(tokens[1]);
		bf.cid = *(tokens[2]) ? tokens[2] : NULL;
		bf.content = *(tokens[3]) ? tokens[3] : NULL;
		broken_holder_remove_content( bh, &bf );
	}
	else if (tokens_length == 5) {
		TRACE("Container matched");
		bf.ip = tokens[0];
		bf.port = atoi(tokens[1]);
		bf.cid = *(tokens[2]) ? tokens[2] : NULL;
		bf.content = *(tokens[3]) ? tokens[3] : NULL;
		bf.cause = *(tokens[4]) ? tokens[4] : NULL;
		broken_holder_remove_content( bh, &bf );
	}
	else {
		WARN("Invalid broken element : [%s]", element);
	}

	g_strfreev(tokens);
}


