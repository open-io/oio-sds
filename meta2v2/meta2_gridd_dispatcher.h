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

#ifndef GRID__META2_GRIDD_DISPATCHER__H
# define GRID__META2_GRIDD_DISPATCHER__H 1

struct gridd_request_descr_s;

/**
 * The easiest way to retrieve the set of exported function out of
 * the META2 backend.
 *
 * All these functions take a meta1_backend_s as first argument.
 */
const struct gridd_request_descr_s* meta2_gridd_get_v1_requests(void);

/**
 * The easiest way to retrieve the set of exported function out of
 * the META2 backend.
 *
 * All these functions take a meta1_backend_s as first argument.
 */
const struct gridd_request_descr_s* meta2_gridd_get_v2_requests(void);

#endif

