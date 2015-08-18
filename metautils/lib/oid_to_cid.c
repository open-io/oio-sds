/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.oid2cid"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "./metautils.h"

static gchar str_id[128];
static gchar bad[] =
{
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	'-', '-', '-', '-', '-', '-', '-', '-', 
	0
};

int
main(int argc, char ** args)
{
	int i;

	for (i=1; i<argc ;i++) {

		struct hc_url_s *url = hc_url_oldinit(args[i]);

		if (url && NULL != hc_url_get_id(url)) {
			memset(str_id, 0, sizeof(str_id));
			oio_str_bin2hex(hc_url_get_id(url), hc_url_get_id_size(url),
					str_id, sizeof(str_id));
			fputs(str_id, stdout);
		}
		else {
			fputs(bad, stdout);
		}

		fputc(' ', stdout);
		fputs(args[i], stdout);
		fputc('\n', stdout);

		if (url)
			hc_url_clean(url);
	}

	fflush(stdout);
	return 0;
}

