/*
OpenIO SDS rdir
Copyright (C) 2017 OpenIO, original work as part of OpenIO SDS

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

#ifndef OIOSDS_RDIR_ROUTES_HPP_
#define OIOSDS_RDIR_ROUTES_HPP_

#ifdef __cplusplus
extern "C" {
#endif

enum rdir_route_e {
    OIO_RDIR_NOT_MATCHED = 0 /* Returned upon error */,
    OIO_ROUTE_STATUS,
    OIO_RDIR_STATUS,
    OIO_RDIR_ADMIN_SHOW,
    OIO_RDIR_ADMIN_UNLOCK,
    OIO_RDIR_ADMIN_LOCK,
    OIO_RDIR_ADMIN_INCIDENT,
    OIO_RDIR_ADMIN_CLEAR,
    OIO_RDIR_VOL_CREATE,
    OIO_RDIR_VOL_PUSH,
    OIO_RDIR_VOL_DELETE,
    OIO_RDIR_VOL_FETCH,
    OIO_RDIR_VOL_STATUS,
};

enum rdir_route_e oio_rdir_parse_route(const char *url);

#ifdef __cplusplus
};
#endif

#endif  /* OIOSDS_RDIR_ROUTES_HPP_ */
