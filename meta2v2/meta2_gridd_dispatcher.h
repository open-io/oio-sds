/*
OpenIO SDS meta2v2
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

#ifndef OIO_SDS__meta2v2__meta2_gridd_dispatcher_h
# define OIO_SDS__meta2v2__meta2_gridd_dispatcher_h 1

struct gridd_request_descr_s;

const struct gridd_request_descr_s* meta2_gridd_get_v1_requests(void);

const struct gridd_request_descr_s* meta2_gridd_get_v2_requests(void);

#endif /*OIO_SDS__meta2v2__meta2_gridd_dispatcher_h*/
