/*
OpenIO SDS rdir
Copyright (C) 2017 OpenIO SAS, original work as part of OpenIO SDS

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

#include <string.h>

#include "routes.h"

/** @private */
struct rdir_router_s {
    const char *ts, *te;
    int cs, act;
};

struct rdir_router_result_s {
	const char *last;
	enum rdir_route_e result;
};

%%{
machine rdir_router_s;
access parser.;

action Final { rc.last = p; }

srv_status = "/status" %{ rc.result = OIO_ROUTE_STATUS; };
srv_config = "/config" %{ rc.result = OIO_ROUTE_CONFIG; };
adm_status = "/v1/status" %{ rc.result = OIO_RDIR_STATUS; };
adm_show = "/v1/rdir/admin/show" %{ rc.result = OIO_RDIR_ADMIN_SHOW; };
adm_lock = "/v1/rdir/admin/lock" %{ rc.result = OIO_RDIR_ADMIN_LOCK; };
adm_unlock = "/v1/rdir/admin/unlock" %{ rc.result = OIO_RDIR_ADMIN_UNLOCK; };
adm_incident = "/v1/rdir/admin/incident" %{ rc.result = OIO_RDIR_ADMIN_INCIDENT; };
adm_clear = "/v1/rdir/admin/clear" %{ rc.result = OIO_RDIR_ADMIN_CLEAR; };
vol_create = "/v1/rdir/create" %{ rc.result = OIO_RDIR_VOL_CREATE; };
vol_push = "/v1/rdir/push" %{ rc.result = OIO_RDIR_VOL_PUSH; };
vol_delete = "/v1/rdir/delete" %{ rc.result = OIO_RDIR_VOL_DELETE; };
vol_fetch = "/v1/rdir/fetch" %{ rc.result = OIO_RDIR_VOL_FETCH; };
vol_status = "/v1/rdir/status" %{ rc.result = OIO_RDIR_VOL_STATUS; };
srv_route = srv_status | srv_config;
adm_route = adm_status | adm_show | adm_lock | adm_unlock | adm_incident | adm_clear;
vol_route = vol_status | vol_fetch | vol_delete | vol_push | vol_create;
any_route = vol_route | adm_route | srv_route;
route_rdir_request := |*
	any_route % Final;
*|;
}%%

%%write data;

static struct rdir_router_result_s _parse(const char *p, const size_t len) {
	struct rdir_router_s parser = {};
    const char* pe = p + len;
    const char* eof = pe;
	struct rdir_router_result_s rc = {};
	rc.result = OIO_RDIR_NOT_MATCHED;
    (void) eof; /* JFS: kept to be ready in case of a FSM change */
    %%write init;
    %%write exec;
	return rc;
}

enum rdir_route_e oio_rdir_parse_route(const char *p) {
    if (!p)
        return OIO_RDIR_NOT_MATCHED;
    const size_t len = strlen(p);
    struct rdir_router_result_s rc = _parse(p, len);

    /* the FSM embed actions that return, here we are when the parsing fails */
    return (p+len) == rc.last ? rc.result : OIO_RDIR_NOT_MATCHED;
}
