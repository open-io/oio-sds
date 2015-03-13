/*
OpenIO SDS sqliterepo
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

#ifndef OIO_SDS__sqliterepo__replication_dispatcher_h
# define OIO_SDS__sqliterepo__replication_dispatcher_h 1

/**
 * @defgroup sqliterepo_gridd Gridd requests dispatcher
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

struct gridd_request_descr_s;

/**
 * The easiest way to retrieve the set of exported function out of
 * the META1 backend.
 *
 * All these functions take a meta1_backend_s as first argument.
 *
 * @return
 */
const struct gridd_request_descr_s* sqlx_repli_gridd_get_requests(void);

/**
 * @return
 */
const struct gridd_request_descr_s * sqlx_sql_gridd_get_requests(void);

/** @} */

#endif /*OIO_SDS__sqliterepo__replication_dispatcher_h*/