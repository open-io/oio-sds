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

#ifndef __HC_H__
#define __HC_H__

#include <hc_url.h>

/************** HC FUNCTIONS (hc_func.c **************/

/**
 * Create a container on Honeycomb. This funcion use meta1v2 requests. (RELEASE-1.6)
 *
 * @param hc
 * @param url the container url
 * @return 0 if an error occured, another value otherwise
 */
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

/**
 * Get a content. This function use features of meta1v2.
 * 
 * @param hc
 * @param url the content url
 * @param dest the path to store the downloaded data
 * @return a pointer.
 */
gs_error_t * hc_get_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *dest, int force, int cache);


/**
 * Delete a container. This function use features of meta1v2.
 * 
 * @param hc
 * @param url the container url
 * @param force if != 0, then destroy the container even if not empty (do flush before destroy)
 * @return a pointer.
 */
gs_error_t * hc_delete_container(gs_grid_storage_t *hc, struct hc_url_s *url, int force);

/**
 * Delete a content. This function use features of meta1v2.
 * 
 * @param hc
 * @param url the content url
 * @return a pointer.
 */
gs_error_t * hc_delete_content(gs_grid_storage_t *hc, struct hc_url_s *url);

/**
 * Get information about an Honeycomb object (container or content)
 * 
 * @param hc
 * @param url the container or content url
 * @param xml if != 0, return info in xml format
 * @param group_chunks if != 0 group together duplicated chunks in output
 * @param result
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_object_info(gs_grid_storage_t *hc, struct hc_url_s *url, int xml, int group_chunks, char **result);

/**
 * Set a property to content. This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @param key
 * @param value
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_func_set_content_property(gs_grid_storage_t *hc, struct hc_url_s *url, char ** args);


/**
 * Get properties to content. This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_func_get_content_properties(gs_grid_storage_t *hc, struct hc_url_s *url, char ***result);

/**
 * Delete a property to content. This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @param key 
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_func_delete_content_property(gs_grid_storage_t *hc, struct hc_url_s *url,char **keys);


/************** HELPS (hc_help.c)*********************/

/*
 * Display func_put help on stderr
 */
void help_put(void);

/*
 * Display func_get help on stderr
 */
void help_get(void);

/*
 * Display func_delete help on stderr
 */
void help_delete(void);

/*
 * Display func_append help on stderr
 */
void help_append(void);

/*
 * Display func_info help on stderr
 */
void help_info(void);

/*
 * Display func_put help on stderr
 */
void help_stgpol(void);

/*
 * Display versioning help on stderr
 */
void help_version(void);

/*
 * Display quota help on stderr
 */
void help_quota(void);

/*
 * Display func_put help on stderr
 */
void help_srvlist(void);

/*
 * Display func_put help on stderr
 */
void help_srvlink(void);

/*
 * Display func_put help on stderr
 */
void help_srvunlink(void);

/*
 * Display func_put help on stderr
 */
void help_srvpoll(void);

/*
 * Display func_put help on stderr
 */
void help_srvforce(void);

/*
 * Display func_put help on stderr
 */
void help_srvconfig(void);

/*
 * Display func_propset help on stderr
 */
void help_propset(void);

/*
 * Display func_propget help on stderr
 */
void help_propget(void);

/*
 * Display func_propdel help on stderr
 */
void help_propdel(void);

#endif /*__HC_H__*/
