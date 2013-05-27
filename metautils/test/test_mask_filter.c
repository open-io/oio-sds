/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>

GByteArray*
load_acl_byte(void)
{
	GByteArray* data = NULL;
	gchar buff[150];
	bzero(buff, sizeof(buff));
	g_snprintf(buff, sizeof(buff), "192.168.10.0 255.255.255.0;192.168.0.0/25");
	data = g_byte_array_new();
	data = g_byte_array_append(data, ((guint8*)buff), strlen(buff)+1);
	return data;
}

void
access_rule_display(gpointer access_rule, gpointer ignored)
{
	(void) ignored;
	printf("access rule = [%s]\n", access_rule_to_string((addr_rule_t*)access_rule));
}

int
main(int argc, char **args)
{
	(void) argc;
	(void) args;
	printf("Starting test\n");
	
	GSList *acl = NULL;
	
	GByteArray* data = NULL;
	data = load_acl_byte();
	acl = parse_acl(data, TRUE);

	/* acl = load_test_acl(); */
	printf("acl_byte loaded\n");

	/* acl = parse_acl_conf_file("/GRID/local/DISK0101/conf/conscience.acl", &error); */

	printf("byte parsed\n");

	g_slist_foreach(acl, access_rule_display, NULL);

	printf("display ok\n");
	

	if(!authorized_personal_only("192.168.10.2", acl)) {
		printf("192.168.10.2 denied\n");
	} else {
		printf("192.168.10.2 allowed\n");
	}

	if(!authorized_personal_only("192.168.0.27", acl)) {
		printf("192.168.0.27 denied\n");
	} else {
		printf("192.168.0.27 allowed\n");
	}

	if(!authorized_personal_only("100.168.10.2", acl)) {
		printf("100.168.10.2 denied\n");
	} else {
		printf("100.168.10.2 allowed\n");
	}

	if(!authorized_personal_only("192.169.10.154", acl)) {
		printf("192.169.10.154 denied\n");
	} else {
		printf("192.169.10.154 allowed\n");
	}

	if(!authorized_personal_only("127.0.0.127", acl)) {
		printf("127.0.0.127 denied\n");
	} else {
		printf("127.0.0.127 allowed\n");
	}

	if(!authorized_personal_only("10.26.95.16", acl)) {
		printf("10.26.95.16 denied\n");
	} else {
		printf("10.26.95.16 allowed\n");
	}

	if(!authorized_personal_only("10.26.95.15", acl)) {
		printf("10.26.95.15 denied\n");
	} else {
		printf("10.26.95.15 allowed\n");
	}

	return 0;
}
