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

#ifndef GRID__GRIDD_DISPATCHER_FILTERS__H
# define GRID__GRIDD_DISPATCHER_FILTERS__H 1

enum gridd_dispatcher_filter_result_e
{
	FILTER_KO=1,
	FILTER_OK,
	FILTER_DONE,
};

/* Forward declarations */
struct gridd_filter_ctx_s;
struct gridd_reply_ctx_s;

/* Meta2 dispatcher filter definition */
typedef int (*gridd_filter)(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply);

#endif
