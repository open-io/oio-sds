/*
OpenIO SDS rainx
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__rainx__mod_dav_rainx_h
# define OIO_SDS__rainx__mod_dav_rainx_h 1

/* the subdirectory to hold all DAV-related information for a directory */
#define DAV_FS_STATE_FILE_FOR_DIR       ".state_for_dir"
#define DAV_FS_LOCK_NULL_FILE           ".locknull"

#include <unistd.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>

#include <metautils/metautils.h>

/* return the storage pool associated with a resource */
apr_pool_t *dav_rainx_pool(const dav_resource *resource);

const dav_hooks_propdb *dav_rainx_get_propdb_hooks(request_rec *r);

void dav_rainx_gather_propsets(apr_array_header_t *uris);

int dav_rainx_find_liveprop(const dav_resource *resource, const char *ns_uri, const char *name, const dav_hooks_liveprop **hooks);

void dav_rainx_insert_all_liveprops(request_rec *r, const dav_resource *resource, dav_prop_insert what, apr_text_header *phdr);

void dav_rainx_register(apr_pool_t *p);

/* Properties callbacks */
extern const dav_hooks_db dav_hooks_db_dbm;

/* per-server configuration */
extern module AP_MODULE_DECLARE_DATA dav_rainx_module;

extern const dav_hooks_repository dav_hooks_repository_rainxinfo;

extern const dav_hooks_repository dav_hooks_repository_rainxstat;

extern const dav_hooks_repository dav_hooks_repository_chunkupdate;


extern dav_error * dav_rainx_stat_get_resource(request_rec *r,
	const char *root_dir, const char *label, int use_checked_in,
	dav_resource **result_resource);

extern dav_error * dav_rainx_info_get_resource(request_rec *r,
	const char *root_dir, const char *label, int use_checked_in,
	dav_resource **result_resource);

#endif /*OIO_SDS__rainx__mod_dav_rainx_h*/
