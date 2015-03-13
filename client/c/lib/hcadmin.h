/*
OpenIO SDS client
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

#ifndef OIO_SDS__client__c__lib__hcadmin_h
# define OIO_SDS__client__c__lib__hcadmin_h 1

gs_error_t * hcadmin_meta1_policy_update(char *ns, gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args);
gs_error_t * hcadmin_touch(              char *url,gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args);

#endif /*OIO_SDS__client__c__lib__hcadmin_h*/