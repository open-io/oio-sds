/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef __SRV_ALERT_HANDLER_H__
# define __SRV_ALERT_HANDLER_H__

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include "./message_handler.h"
#include "./srvalert.h"

int
srv_send_alert(const char *id, const char *criticity, const char *msg)
{
	EXTRA_ASSERT(id != NULL);
	EXTRA_ASSERT(criticity != NULL);
	EXTRA_ASSERT(msg != NULL);
	GRID_ERROR(id, "%s:%s", criticity, msg);
	return 1;
}

int
srv_send_valert(const char *id, const char *criticity, const char *fmt, va_list args)
{
	EXTRA_ASSERT(id != NULL);
	EXTRA_ASSERT(criticity != NULL);
	EXTRA_ASSERT(fmt != NULL);
	char formatted_msg[8192];
	g_vsnprintf(formatted_msg, sizeof(formatted_msg) - 1, fmt, args);
	return srv_send_alert(id, criticity, formatted_msg);
}

int
srv_send_falert(const char *id, const char *criticity, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int rc = srv_send_valert(id, criticity, fmt, args);
	va_end(args);
	return rc;
}

#endif /*__SRV_ALERT_HANDLER_H__*/
