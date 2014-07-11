#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "conscience.api"
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "./conscience.h"
#include "./conscience_srvtype.h"
#include "./conscience_broken_holder_common.h"
#include "./conscience_broken_holder.h"

void
broken_holder_fix_meta1(struct broken_holder_s * bh, struct broken_fields_s *bf)
{
	broken_meta1_t *brk_meta1;
	addr_info_t *addr;

	addr = build_addr_info(bf->ip, bf->port, NULL);
	if (!addr) {
		INFO("Failed to fix META1=[%s:%i]", bf->ip, bf->port);
		return;
	}

	brk_meta1 = g_hash_table_lookup(bh->ht_meta1, addr);
	if (brk_meta1) {
		if (0 >= (-- brk_meta1->counter)) {
			INFO("META1=[%s:%i] has been totally fixed", bf->ip, bf->port);
			g_hash_table_remove( bh->ht_meta1, addr);
		} else {
			INFO("META1=[%s:%i] has been partially fixed", bf->ip, bf->port);
		}
	}

	g_free(addr);
	return ;
}

void
broken_holder_fix_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf)
{
	addr_info_t *addr;
	broken_meta2_t *brk_m2;

	addr = build_addr_info(bf->ip, bf->port, NULL);
	if (!addr) {
		INFO("Failed to fix the META2=[%s:%i]", bf->ip, bf->port);
		return ;
	}

	brk_m2 = g_hash_table_lookup(bh->ht_meta2, addr);
	if (brk_m2) {
		if (brk_m2->totally_broken) {
			INFO("META2=[%s:%i] is not totally broken", bf->ip, bf->port);
		} else if (0>=(--brk_m2->counter)) {
			INFO("META2=[%s:%i] has been totally fixed", bf->ip, bf->port);
			g_hash_table_remove( bh->ht_meta2, addr );
		} else {
			INFO("META2=[%s:%i] has been partially fixed", bf->ip, bf->port);
		}
	}

	g_free(addr);
	return ;
}

void
broken_holder_fix_content(struct broken_holder_s * bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2)
{
	struct broken_content_s *brk_content;
	char key[STRLEN_CONTAINERID + LIMIT_LENGTH_CONTENTPATH + 1];

	(void)bh;
	memset(key, '\0', sizeof(key));
	g_snprintf(key, sizeof(key), "%s:%s", bf->cid, bf->content);

	brk_content = g_hash_table_lookup(brk_m2->broken_containers, key);
	if (!brk_content) {
		DEBUG("Content [%s/%s/%s] not broken", bf->ns, bf->cid, bf->content);
	} else {
		if (0 >= (-- brk_content->counter)) {
			INFO("Content [%s/%s/%s] totally fixed", bf->ns, bf->cid, bf->content);
			g_hash_table_remove( brk_m2->broken_containers, key);
		} else {
			INFO("Content [%s/%s/%s] partially fixed", bf->ns, bf->cid, bf->content);
		}
	}
}

void
broken_holder_fix_container(struct broken_holder_s * bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2)
{
	struct broken_content_s *brk_content;
	char key[STRLEN_CONTAINERID + LIMIT_LENGTH_CONTENTPATH + 1];

	(void)bh;
	memset(key, '\0', sizeof(key));
	g_snprintf(key, sizeof(key), "%s:all", bf->cid);

	brk_content = g_hash_table_lookup(brk_m2->broken_containers, key);
	if (!brk_content) {
		DEBUG("Container [%s/%s] not broken", bf->ns, bf->cid);
	} else {
		if (0 >= (--brk_content->counter)) {
			INFO("Container [%s/%s] totally fixed", bf->ns, bf->cid);
			g_hash_table_remove( brk_m2->broken_containers, key);
		}
		else {
			INFO("Container [%s/%s] partially fixed", bf->ns, bf->cid);
		}
	}
}

static void
_fix_in_one_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2)
{
	if (!brk_m2) {
		DEBUG("META2=[%s:%i] not broken, not fixing [%s/%s/%s]",
			bf->ip, bf->port, bf->ns, bf->cid, bf->content);
		return;
	}

	if (brk_m2->totally_broken) {
		INFO("META2=[%s:%i] is totally broken, not fixing [%s/%s/%s]",
			bf->ip, bf->port, bf->ns, bf->cid, bf->content);
		return;
	}

	if (bf->content)
		broken_holder_fix_content(bh, bf, brk_m2);
	else
		broken_holder_fix_container(bh, bf, brk_m2);
}

static void
_fix_in_all_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf)
{
	GHashTableIter iter;
	gpointer k, v;
	
	g_hash_table_iter_init(&iter, bh->ht_meta2);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		struct broken_meta2_s *brk_m2 = v;	
		_fix_in_one_meta2(bh, bf, brk_m2);
	}
}

void
broken_holder_fix_in_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf)
{
	addr_info_t *addr;

	if (bf->port == 0 || !(addr = build_addr_info(bf->ip, bf->port, NULL))) {
		INFO("META2 address [%s:%i] malformed, fixing [%s/%s/%s] in all meta2",
			bf->ip, bf->port, bf->ns, bf->cid, bf->content);
		_fix_in_all_meta2(bh, bf);
	}
	else {
		_fix_in_one_meta2(bh, bf, g_hash_table_lookup(bh->ht_meta2, addr));
		g_free(addr);
	}
}

void
broken_holder_fix_element(struct broken_holder_s *bh, const gchar *element)
{
	gchar **tokens;
	gsize tokens_length;
	struct broken_fields_s bf;

	if (!bh || !element) {
		errno = EINVAL;
		return ;
	}

	memset(&bf,0x00,sizeof(bf));
	bf.packed = element;
	bf.ns = bh->conscience->ns_info.name;

	tokens = g_strsplit(element,":",0);
	if (!tokens) {
		errno = EBADMSG;
		return;
	}
	tokens_length = g_strv_length(tokens);
	
	/*special case for the broken META1 */
	if (tokens_length == 3 && g_ascii_strcasecmp(tokens[0],"META1")) {
		bf.ip = tokens[1];
		bf.port = atoi(tokens[2]);
		broken_holder_fix_meta1(bh, &bf);
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
			broken_holder_fix_in_meta2(bh, &bf);
			break;
		case 2:
			broken_holder_fix_meta2(bh, &bf);
			break;
		}
	}
	else {
		WARN("Invalid broken element : [%s]", element);
		errno = EPROTO;
	}

	g_strfreev(tokens);
}

