#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils"
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "metautils.h"
#include "metautils_syscall.h"

void
addr_rule_g_free(gpointer data)
{
	addr_rule_t* r = (addr_rule_t*)data;
	if(!r)
		return;
	if(r->network_addr)
		g_free(r->network_addr);
	if(r->network_mask)
		g_free(r->network_mask);
	
	g_free(r);
}

/* FIX ME, I DON'T WORK WITH IPv6 */
static gboolean
_rule_match(const gchar* addr, addr_rule_t* rule)
{
	gboolean match = TRUE;
	gchar* mask = NULL;
	gchar** mask_tokens = NULL;
	gchar** addr_tokens = NULL;
	gchar** network_tokens = NULL;

	mask_tokens = g_strsplit(rule->network_mask, ".", 4);
	addr_tokens = g_strsplit(addr, ".", 4);
	network_tokens = g_strsplit(rule->network_addr, ".", 4);

	if(g_strv_length(mask_tokens) != 4 || g_strv_length(mask_tokens) != 4 || g_strv_length(network_tokens) != 4) {
		DEBUG("Failed to process acl mask [%s] on client addr [%s] (network [%s])", mask, addr, rule->network_addr);	
		goto label_exit;
	}

	gint64 network_int, addr_int, mask_int;

	for (int i =0; i < 4; i++) {
		network_int = g_ascii_strtoll(network_tokens[i], NULL, 10);
		addr_int = g_ascii_strtoll(addr_tokens[i], NULL, 10);
		mask_int = g_ascii_strtoll(mask_tokens[i], NULL, 10);
		if ((network_int & mask_int) != (addr_int & mask_int)) {
			match = FALSE;
			break;
		}
	}
	
label_exit:
	g_strfreev(network_tokens);
	g_strfreev(mask_tokens);
	g_strfreev(addr_tokens);
	g_free(mask);
	return match;
}

gboolean
authorized_personal_only(const gchar *addr, GSList* acl)
{
	GSList* l = NULL;
	/* sanity check */
	
	if (!addr) {
		DEBUG("Missing parameter to test access: %p",addr);
		return FALSE;
	}
	
	/* if no acl, no access check, allow... */
	if (!acl) {
		DEBUG("acl NULL, consider user authorized");
		return TRUE;
	}
	
	for (l=acl; l ;l=l->next) {
		if (_rule_match(addr, ((addr_rule_t*)l->data))) {
			return ((addr_rule_t*)l->data)->authorize;
		}
	}

	/* if no rules match, reject */
	return FALSE;
}

static gchar*
_range2netmask(gchar* ip_range) {
	int i; 
	int netmask[4];
	gchar buf[1024];
	gchar** ip_range_split = NULL;
	ip_range_split = g_strsplit(ip_range, "/", 2);	
	i = atoi(ip_range_split[1]);	
	
	int octet_full, last = 0;	
	octet_full = i / 8;
	last = i % 8;
	for(int j=0; j < octet_full;j++)
		netmask[j]= 255; 
	for(int j=octet_full; j < 4; j++) {
		netmask[j] = 0;
		if (last != 0) {
			for (int k = 1; k <= last; k++) {
				netmask[j] = netmask[j] | 2 << ((8-k) - 1);	
			}
			last = 0;
		}	
	}
	bzero(buf, sizeof(buf));
	g_snprintf(buf, sizeof(buf), "%s %d.%d.%d.%d",ip_range_split[0], netmask[0], netmask[1], netmask[2], netmask[3]);
	g_strfreev(ip_range_split);
	return g_strdup(buf);
}

static GSList*
_parse_acl_bytes(const GByteArray* acl_byte)
{
	/* sanity check */
	GError* error = NULL;

	if(!acl_byte || !acl_byte->data || acl_byte->len == 0)	{
		return NULL;
	}
		
	GSList* result = NULL;
	gchar** access_rules = NULL;
	
	access_rules = g_strsplit(((char*)acl_byte->data), "\n", 0);

	GRegex *range_regex = NULL;
	range_regex = g_regex_new("([0-9]{1,3}.){3}[0-9]{1,3}/[0-9]{1,2}", 0, 0, &error);

	int i, max;

	for(i=0,max=g_strv_length(access_rules); i<max; i++) {
		addr_rule_t* rule = NULL;
		rule = g_malloc0(sizeof(addr_rule_t));

		if (!access_rules[i] || !*(access_rules[i]))
			continue;

		/* regex matching [X.X.X.X/X xxxx] or [X.X.X.X X.X.X.X xxxx] or [xxxx X.X.X.X] */
		if(g_str_has_prefix(access_rules[i], "host")) {
			rule->authorize = TRUE;
			gchar** splits = NULL;	
			splits = g_strsplit(access_rules[i], " ", 2);	
			rule->network_addr = g_strdup(splits[1]);	
			gchar buff[50];
			bzero(buff, sizeof(buff));	
			g_snprintf(buff, sizeof(buff), "255.255.255.255");
			rule->network_mask = g_strdup(buff); 
			g_strfreev(splits);
		} else {
			gchar** line_splits = NULL;
			line_splits = g_strsplit(access_rules[i], " ", 0);
			if (g_strv_length(line_splits) == 3) {
				rule->network_addr = g_strdup(line_splits[0]);
				rule->network_mask = g_strdup(line_splits[1]);
			}
			else {
				if(g_regex_match_full(range_regex, line_splits[0], strlen(line_splits[0]), 0, 0, NULL, &error)) {
					gchar** tmp_array = NULL;
					gchar* tmp = NULL;
					tmp = _range2netmask(line_splits[0]);
					tmp_array = g_strsplit(tmp, " ", 2);
					rule->network_addr = g_strdup(tmp_array[0]);
					rule->network_mask = g_strdup(tmp_array[1]);
					g_free(tmp);
					g_strfreev(tmp_array);
				} else {
					/* Failed to read line */
				}

				if(g_str_has_suffix(access_rules[i],"allow")) 
					rule->authorize = TRUE;
				else
					rule->authorize = FALSE;
			}
			g_strfreev(line_splits);
		}
		result = g_slist_prepend(result, rule);
	}

	g_strfreev(access_rules);

	return g_slist_reverse(result);
}

/**
 * For parse informations from dedicated file
 * FIXME TODO XXX File loading managed by glib2  : g_file_get_contents()
 * FIXME TODO XXX duplicated in cluster/lib/gridcluster.c : gba_read()
 */

GSList*
parse_acl_conf_file(const gchar* file_path, GError **error)
{
	/* TODO: open file and read it line by line */
	int fd;
	ssize_t r;
	guint8 buff[256];
	GByteArray* data = NULL;
	GSList* result = NULL;
	fd = metautils_syscall_open(file_path, O_RDONLY, 0);

	if (fd == -1) {
		GSETERROR(error, "Failed to open file [%s] : %s", file_path, strerror(errno));
                return NULL;
	}

	data = g_byte_array_new();

	while ((r = metautils_syscall_read(fd, buff, sizeof(buff))) > 0) {
                data = g_byte_array_append(data, buff, r);
        }
	
	metautils_pclose(&fd);

        if (r < 0) {
                GSETERROR(error, "Failed to read data from file [%s] : %s", file_path, strerror(errno));
                g_byte_array_free(data, TRUE);
                return NULL;
        }

	result = _parse_acl_bytes(data);

	return result;
}

/* For parse informations from namespace info => like X.X.X.X X.X.X.X;X.X.X.X/X; */
	
GSList*
parse_acl(const GByteArray* acl_byte, gboolean authorize)
{
	/* sanity check */
	GError* error = NULL;

	if(!acl_byte || !acl_byte->data || acl_byte->len == 0)	{
		return NULL;
	}
		
	GSList* result = NULL;
	gchar** access_rules = NULL;
	
	access_rules = g_strsplit(((char*)acl_byte->data), ";", 0);
	
	GRegex *range_regex = NULL;
	range_regex = g_regex_new("([0-9]{1,3}.){3}[0-9]{1,3}/[0-9]{1,2}", 0, 0, &error);

	for(int i = 0; i < ((int)g_strv_length(access_rules)); i++) {
		addr_rule_t* rule = NULL;
		rule = g_malloc0(sizeof(addr_rule_t));
		if((access_rules[i] == NULL) || (strlen(access_rules[i])<=1))
			continue;

		/* regex matching [X.X.X.X/X] */
		gchar** tmp_array = NULL;
		if(g_regex_match_full(range_regex, access_rules[i], strlen(access_rules[i]), 0, 0, NULL, &error)) {
			gchar* tmp = NULL;
			tmp = _range2netmask(access_rules[i]);
			tmp_array = g_strsplit(tmp, " ", 2);
			rule->network_addr = g_strdup(tmp_array[0]);
			rule->network_mask = g_strdup(tmp_array[1]);
			g_free(tmp);
		} else {
			tmp_array = g_strsplit(access_rules[i], " ", 2);
			rule->network_addr = g_strdup(tmp_array[0]);
			rule->network_mask = g_strdup(tmp_array[1]);
		}
		rule->authorize = authorize;
		result = g_slist_prepend(result, rule);
		g_strfreev(tmp_array);
	}
	g_regex_unref(range_regex);

	g_strfreev(access_rules);

	return g_slist_reverse(result);
}

gchar* 
access_rule_to_string(const addr_rule_t* addr_rule) {

	gchar tmp[1024];
	bzero(tmp, sizeof(tmp));
	g_snprintf(tmp, sizeof(tmp), "network = [%s] | netmask = [%s] | authorize = [%d]",addr_rule->network_addr, 
		addr_rule->network_mask, addr_rule->authorize);	
	return g_strdup(tmp);
}
