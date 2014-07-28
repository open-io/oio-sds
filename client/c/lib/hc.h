#ifndef __HC_H__
#define __HC_H__

struct hc_url_s;

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
gs_error_t * hc_get_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *dest, int force, int cache, gchar *stgpol);

/**
 * Download a content to writer specified in dl_info.
 *
 * @param hc
 * @param url
 * @param dl_info
 * @param cache
 * @param stgpol
 * @return
 */
gs_error_t * hc_dl_content(gs_grid_storage_t *hc, struct hc_url_s *url, gs_download_info_t *dl_info, int cache, gchar *stgpol);

/**
 * Delete a container. This function use features of meta1v2.
 * 
 * @param hc
 * @param url the container url
 * @param force if != 0, then destroy the container even if not empty (do flush before destroy)
 * @return a pointer.
 */
gs_error_t * hc_delete_container(gs_grid_storage_t *hc, struct hc_url_s *url, int force, int flush);

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
 * @param result
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_object_info(gs_grid_storage_t *hc, struct hc_url_s *url, int xml, char **result);

/**
 * Set a property to content or container. This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @param key
 * @param value
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_func_set_property(gs_grid_storage_t *hc, struct hc_url_s *url, char **args);

/**
 * Get properties to content. This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_func_get_content_properties(gs_grid_storage_t *hc, struct hc_url_s *url, char ***result);

/**
 * Delete a property from content/container. This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @param key
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
gs_error_t * hc_func_delete_property(gs_grid_storage_t *hc, struct hc_url_s *url,char **keys);

/**
 * Create a copy of a content (intra container). This function use features of meta2v2.
 * @param hc
 * @param url the content url
 * @param src
 * @return a pointer to a gs_erorr_t if an error occured, NULL otherwise
 */
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

/**
 * Take a snapshot of a container.
 *
 * @param hc
 * @param url The URL of the container, with the snapshot name as a query string
 */
gs_error_t *hc_func_take_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url);

/**
 * Delete a snapshot from a container.
 *
 * @param hc
 * @param url The URL of the container, with the snapshot name as a query string
 */
gs_error_t *hc_func_delete_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url);

/**
 * Restore the state of container or a content.
 *
 * @param hc
 * @param url The URL of the container or content, with the snapshot name as
 *   a query string
 * @param hard_restore If true, erase all contents more recent than the snapshot
 */
gs_error_t *hc_func_restore_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url,
		int hard_restore);


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

/*
 * Display func_snapXXX help on stderr
 */
void help_snaplist(void);
void help_snaptake(void);
void help_snapdel(void);
void help_snaprestore(void);

#endif /*__HC_H__*/
