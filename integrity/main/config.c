/*
OpenIO SDS integrity
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.config"
#endif

#include <metautils/lib/metautils.h>

#include "config.h"

gboolean
load_config(struct integrity_loop_config_s** config, GError** error)
{
        CHECK_ARG_POINTER(config, error);

	*config = g_try_new0(struct integrity_loop_config_s, 1);
	CHECK_POINTER_ALLOC(*config, error);

        (*config)->nb_volume_scanner_thread = 5;
	(*config)->chunk_crawler_sleep_time = 100;
	(*config)->chunk_checker_sleep_time = 100;

        return TRUE;
}
