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

#ifndef OIO_SDS__client__c__lib__hc_h
# define OIO_SDS__client__c__lib__hc_h 1

struct hc_url_s;

/************** HC FUNCTIONS (hc_func.c **************/

/** Create a container on a namespace. */
gs_error_t * hc_create_container(gs_grid_storage_t *hc, struct hc_url_s *url, const char *stgpol, const char *versioning);

/**
 * Upload a content in a container. This function use features of meta1v2.
 * 
 * @param hc
 * @param url the content url
 * @param local_path the path where the content's data to upload is stored 
 * @param metadata user's metadata to add to the uploaded content
 * @param sys_metadata system's metadata to add to the uploaded content
 * @param ac autocreate flag. If not 0, it the container in which you upload the content
 * 		is not yet created, it will be created on the fly.
 * @return 0 if an error occured, another value otherwise.
 */
gs_error_t * hc_put_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *local_path,
		const char *metadata, const char *sys_metadata, int ac);

/**
 * Append data to a content in a container. This function use features of meta1v2.
 *
 * @param hc
 * @param url the content url
 * @param local_path the path where the content's data to upload is stored
 * @return 0 if an error occured, another value otherwise.
 */
gs_error_t * hc_append_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *local_path);

/**
 * List all contents in a container. This function use features of meta1v2.
 * 
 * @param hc
 * @param url the container url
 * @param output_xml if != 0, the result will be xml formated
 * @param show_size if != 0, the size of each content will be prefixed with its size
 * @param result the contents listing string formated
 * @return 0 if an error occured, another value otherwise.
 */
gs_error_t * hc_list_contents(gs_grid_storage_t *hc, struct hc_url_s *url, int output_xml, int show_info,
		char **result);

/** Get a content. This function use features of meta1v2. */
gs_error_t * hc_get_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *dest, int force, int cache, gchar *stgpol);

/** Download a content to writer specified in dl_info. */
gs_error_t * hc_dl_content(gs_grid_storage_t *hc, struct hc_url_s *url, gs_download_info_t *dl_info, int cache, gchar *stgpol);

/** Delete a container. This function use features of meta1v2. */
gs_error_t * hc_delete_container(gs_grid_storage_t *hc, struct hc_url_s *url, int force, int flush);

/** Delete a content. This function use features of meta1v2.  */
gs_error_t * hc_delete_content(gs_grid_storage_t *hc, struct hc_url_s *url);

/** Get information about an object (container or content) */
gs_error_t * hc_object_info(gs_grid_storage_t *hc, struct hc_url_s *url, int xml, char **result);

/** Set a property to content or container. This function use features of meta2v2. */
gs_error_t * hc_func_set_property(gs_grid_storage_t *hc, struct hc_url_s *url, char **args);

/** Get properties to content. This function use features of meta2v2. */
gs_error_t * hc_func_get_content_properties(gs_grid_storage_t *hc, struct hc_url_s *url, char ***result);

/** Delete a property from content/container. This function use features of meta2v2. */
gs_error_t * hc_func_delete_property(gs_grid_storage_t *hc, struct hc_url_s *url,char **keys);

/** Create a copy of a content (intra container). This function use features of meta2v2. */
gs_error_t * hc_func_copy_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *source);

/**
 * List snapshots of a container.
 *
 * @param hc
 * @param url The URL of the container
 * @param output_xml Output result as an XML string instead of human-readable
 * @param show_info Display extended information about snapshots
 * @param[out] result Where to put the result string
 */
gs_error_t * hc_func_list_snapshots(gs_grid_storage_t *hc, struct hc_url_s *url,
		int output_xml, int show_info, char **result);

/** Take a snapshot of a container. */
gs_error_t *hc_func_take_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url);

/** Delete a snapshot from a container. */
gs_error_t *hc_func_delete_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url);

/** Restore the state of container or a content. If <hard_restore> is true,
 * erase all contents more recent than the snapshot */
gs_error_t *hc_func_restore_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url,
		int hard_restore);

#endif /*OIO_SDS__client__c__lib__hc_h*/
