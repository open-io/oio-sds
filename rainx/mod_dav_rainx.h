/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file  mod_dav_rainx.h
 * @brief Declarations for the filesystem repository implementation
 *
 * @addtogroup MOD_DAV
 * @{
 */

#ifndef _DAV_FS_REPOS_H_
#define _DAV_FS_REPOS_H_

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

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>


/* return the storage pool associated with a resource */
apr_pool_t *dav_rainx_pool(const dav_resource *resource);

const dav_hooks_propdb *dav_rainx_get_propdb_hooks(request_rec *r);

void dav_rainx_gather_propsets(apr_array_header_t *uris);

int dav_rainx_find_liveprop(const dav_resource *resource, const char *ns_uri, const char *name, const dav_hooks_liveprop **hooks);

void dav_rainx_insert_all_liveprops(request_rec *r, const dav_resource *resource, dav_prop_insert what, apr_text_header *phdr);

void dav_rainx_register(apr_pool_t *p);

/* ------------------------------------------------------------------------- */

/* Properties callbacks */
extern const dav_hooks_db dav_hooks_db_dbm;

/* per-server configuration */
extern module AP_MODULE_DECLARE_DATA dav_rainx_module;

extern const dav_hooks_repository dav_hooks_repository_rainxinfo;

extern const dav_hooks_repository dav_hooks_repository_rainxstat;

extern const dav_hooks_repository dav_hooks_repository_chunkupdate;

/* extern const dav_hooks_repository dav_hooks_repository_rainx; */

/* ------------------------------------------------------------------------- */

extern dav_error * dav_rainx_stat_get_resource(request_rec *r,
	const char *root_dir, const char *label, int use_checked_in,
	dav_resource **result_resource);

extern dav_error * dav_rainx_info_get_resource(request_rec *r,
	const char *root_dir, const char *label, int use_checked_in,
	dav_resource **result_resource);

/* ------------------------------------------------------------------------- */

#endif /* _DAV_FS_REPOS_H_ */
/** @} */

