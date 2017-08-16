/*
OpenIO SDS server
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__server__gridd_dispatcher_filters_h
# define OIO_SDS__server__gridd_dispatcher_filters_h 1

enum gridd_dispatcher_filter_result_e
{
	FILTER_KO,
	FILTER_OK,
};

/* Forward declarations */
struct gridd_filter_ctx_s;
struct gridd_reply_ctx_s;

/* Meta2 dispatcher filter definition */
typedef int (*gridd_filter)(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply);

#endif /*OIO_SDS__server__gridd_dispatcher_filters_h*/
