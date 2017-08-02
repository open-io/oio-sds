/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__meta1v2__meta1_gridd_dispatcher_h
# define OIO_SDS__meta1v2__meta1_gridd_dispatcher_h 1

/**
 * @addtogroup meta1v2_gridd 
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
const struct gridd_request_descr_s* meta1_gridd_get_requests(void);

/** @} */

#endif /*OIO_SDS__meta1v2__meta1_gridd_dispatcher_h*/