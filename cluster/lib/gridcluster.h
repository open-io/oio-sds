/**
 * @file gridcluster.h
 * Cluster information access library
 */

#ifndef _GRIDCLUSTER_H
#define _GRIDCLUSTER_H

/**
 * @ingroup gridcluster_lib
 * @{
 */

#include <metautils/lib/metatypes.h>
#include <cluster/agent/gridagent.h>
#include <cluster/events/gridcluster_eventhandler.h>

/** The path to the grid config file */
#define CONFIG_FILE_PATH "/etc/gridstorage.conf"

/**  */
#define NS_ACL_ALLOW_OPTION "allow"

/**  */
#define NS_ACL_DENY_OPTION "deny"

#ifndef GCLUSTER_CONFIG_DIR_PATH
# define GCLUSTER_CONFIG_DIR_PATH "/etc/gridstorage.conf.d"
#endif

/**
 * @see gridcluster_list_ns()
 */
#define GCLUSTER_CFG_LOCAL 1

/**
 * @see gridcluster_list_ns()
 */
#define GCLUSTER_CFG_NS    2


/**
 * Struct to store an agent task description
 */
struct task_s {
	char id[MAX_TASKID_LENGTH];	/**< The task id */
	long next_schedule;		/**< The date of the next execution of the task */
	gboolean busy;			/**< A flag set to TRUE if the task is running */
};

/**
 * Get the namespace infos
 *
 * @param ns_name the namespace name
 * @param error
 *
 * @return an allocated namespace_info_t or NULL if an error occured (error is set).
 * The returned namespace_info_t should be freed with namespace_info_free()
 */
namespace_info_t *get_namespace_info(const char *ns_name, GError **error);

/**
 * Get the META0 infos
 *
 * @param ns_name the namespace name
 * @param error
 * @return an allocated meta0_info_t or NULL if an error occured (error is set).
 * The returned meta0_info_t should be freed with g_free()
 */
meta0_info_t *get_meta0_info(const char *ns_name, GError **error);

/**
 * Get the META0 infos, and the network operations should not take longer
 * thanthe given number of milliseconds.
 *
 * @param ns_name the namespace name
 * @param timeout_cnx timeout on connect()
 * @param timeout_req timeout on read()/write()
 * @param error
 *
 * @return an allocated meta0_info_t or NULL if an error occured (error is set).
 * The returned meta0_info_t should be freed with g_free()
 */
meta0_info_t *get_meta0_info2(const char *ns_name, long timeout_cnx, long timeout_req, GError **error);

/**
 * Count the number of service of a given type in a namespace
 *
 * @param ns_name the namespace name
 * @param type the type of service to count
 * @param error
 *
 * @return the number of service or -1 if an error occured (error is set)
 */
gint count_namespace_services(const char *ns_name, const char *type, GError **error);

/**
 * List services of a given type in a namespace.
 * list_namespace_services() fails if gridagent not available,
 * list_namespace_services2() fallbacks on conscience.
 *
 * @param ns_name the namespace name
 * @param type the type of service to list
 * @param error
 *
 * @return a list of service_info_t or NULL if an error occured (error is set)
 */
GSList* list_namespace_services(const char *ns_name, const char *type, GError **error);
GSList* list_namespace_services2(const char *ns_name, const char *type, GError **error);

/**
 * Get the first service of a given type in a namespace
 *
 * @param ns_name the namespace_name
 * @param type_name the type of the service
 * @param error

 * @return an allocated service_info_s or NULL if an error occured (error is set)
 * The returned service_info_s should be freed with service_info_clean()
 */
struct service_info_s* get_one_namespace_service(const gchar *ns_name, const gchar *type_name, GError **error);

/**
 * List the types of services available in a namespace
 *
 * @param ns_name the namespace name
 * @param error
 *
 * @return a list of type names in string format or NULL if an error occured (error is set)
 */
GSList* list_namespace_service_types(const char *ns_name, GError **error);

/**
 * Register a service in a namespace
 *
 * @param si the service to register
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int register_namespace_service(const struct service_info_s *si, GError **error);

/**
 * List all services running locally on the server
 *
 * @param error
 *
 * @return a list of service_info_s or NULL if an error occured (error is set)
 */
GSList *list_local_services(GError **error);

/**
 * Unregister all services of a given type from a namespace
 *
 * @param ns_name the namespace name
 * @param type the service type
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int clear_namespace_services(const char *ns_name, const char *type, GError **error);

/**
 * Store an erroneous META1 alert in the conecience of a namespace
 *
 * @param ns_name the namespace name
 * @param m1_addr the address of the META1
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int store_erroneous_meta1( const char *ns_name, const addr_info_t *m1_addr, GError **error );

/**
 * Store an erroneous container alert in the conecience of a namespace
 *
 * @param ns_name the namespace name
 * @param cID the container id
 * @param src_addr the address of the META2 which hosts the container
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int store_erroneous_container( const char *ns_name, const container_id_t cID,
	addr_info_t *src_addr, GError **error );

/**
 * Store an erroneous content alert in the conecience of a namespace
 *
 * @param ns_name the namespace name
 * @param cID the container id 
 * @param src_addr the address of the META2 which hosts the container
 * @param error
 * @param path the content name
 * @param cause a string (NULL-terminated) that is the cause of the content break (optional)
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int store_erroneous_content( const char *ns_name, const container_id_t cID,
	addr_info_t *src_addr, GError **error, const gchar *path, const gchar *cause );

/**
 * Tell the conscience of a namespace that everything was done locally to fix a META1
 *
 * @param ns_name the namespace name
 * @param error
 * @param m1_addr the META1 address
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int fixed_erroneous_meta1( const char *ns_name, GError **error, addr_info_t *m1_addr);

/**
 * Tell the conscience of a namespace that everything was done locally to fix a container / content
 *
 * @param ns_name the namespace name
 * @param cID the container id
 * @param error
 * @param path the content name (optional : if not set we consider the container was fixed)
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int fixed_erroneous_content( const char *ns_name, const container_id_t cID, GError **error, const gchar *path);

/**
 * Tells the conscience of a namespace to remove all broken alerts from its memory
 *
 * @param ns_name the namespace name
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int flush_erroneous_elements( const char *ns_name, GError **error );

/**
 * Tells the conscience of a namespace to remove all broken containers alerts from its memory
 *
 * @param ns_name the namespace name
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
GSList* fetch_erroneous_containers( const char *ns_name, GError **error );

/**
 * Parse the grid config file CONFIG_FILE_PATH
 *
 * @param ns_hash an allocated hashtable string:string which will be filled with the result of the parsing
 * @param error
 *
 * @return 1 or 0 if an error occured (error is set)
 */
int parse_cluster_config(GHashTable *ns_hash, GError **error);

/**
 * List internal tasks of the agent
 *
 * @param error
 *
 * @return a list of task_s or NULL if an error occured
 */
GSList *list_tasks(GError **error);

/**
 * Encodes the event in a agent-suitable form and then call
 * send_encoded_event_to_agent().
 *
 * @param ns_name the namespace name
 * @param event the event to send
 * @param err
 *
 * @return TRUE or FALSE if an error occured
 */
gboolean event_send_to_agent( const gchar *ns_name, gridcluster_event_t *event, GError **err );

/**
 * Ask to the local agent the list of sercice-type names that have
 * an event handler configuration in the namespace. These are allowed
 * to send events, because all the events belonging to another service
 * type will fallback on a DROP action.
 *
 * @param ns_name the namespace name
 * @param err 
 *
 * @return a list of service types names or NULL if an error occured (err is set)
 */
GSList* event_get_managed_patterns(const gchar *ns_name, GError **err);

/**
 * Get the event handler configuration for a namespace
 *
 * @param ns_name the namespace name
 * @param err
 *
 * @return the configuration in string format
 */
GByteArray* event_get_configuration(const gchar *ns_name, GError **err);

/**
 * UNUSED !!!
 */
GByteArray* get_srvtype_configuration(const gchar *ns_name, const gchar *type_name, GError **error);

/**
 * Extract mode worm state from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return TRUE if namespace is in mode worm, FALSE otherwise
 */
gboolean namespace_in_worm_mode(namespace_info_t* ns_info);

/**
 * Extract container max size allowed from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return the container max size allowed
 */
gint64 namespace_container_max_size(namespace_info_t* ns_info);

/**
 * Get chunk size for a specific VNS.
 *
 * @param ns_info the namespace info
 * @param ns_name the full name of the VNS to get chunk size of
 * @return the chunk size for the specified VNS, or the global one
 *   if not defined for this VNS.
 */
gint64 namespace_chunk_size(const namespace_info_t* ns_info, const char *ns_name);

/**
 * Extract namespace defined storage_policy from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return the storage_policy defined (must be freed)
 */
gchar* namespace_storage_policy(const namespace_info_t* ns_info, const char *ns_name);

/**
 * Check if a storage policy exist for a namespace
 *
 * @param ns_info the namespace_info
 *
 * @param storage_policy the namespace_info
 *
 * @return TRUE if the storage policy exist, FALSE otherwise
 */
gboolean namespace_is_storage_policy_valid(const namespace_info_t* ns_info, const gchar *storage_policy);

/**
 * Return the value of a data security matching a storage policy (the string "DATASEC:PARAM1:PARAM2:...")
 *
 * @param ns_info the namespace_info
 *
 * @param wanted_policy the policy to extract data security value. If null, get the data security matching the namespace configured policy
 *
 * @return the data security "value"
 */
gchar* namespace_data_security_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

/**
 * Return the "value" of a storage policy (the string "STG_CLASS:DATA_SEC:DATA_THREAT")
 *
 * @param ns_info the namespace_info
 *
 * @param wanted_policy the policy to extract data security value. If null, get the data security matching the namespace configured policy
 *
 * @return the storage_policy "value" (must be freed)
 */
gchar* namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

/**
 * Extract mode compression state from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return TRUE if namespace is in mode compression, FALSE otherwise
 */
gboolean namespace_in_compression_mode(namespace_info_t* ns_info);

/**
 * @param ns_info
 * @return
 */
gsize namespace_get_autocontainer_src_offset(namespace_info_t* ns_info);

/**
 * @param ns_info
 * @return
 */
gsize namespace_get_autocontainer_src_size(namespace_info_t* ns_info);

/**
 * @param ns_info
 * @return
 */
gsize namespace_get_autocontainer_dst_bits(namespace_info_t* ns_info);

/**
 * Only used by gridd
 * @param error
 * @return
 */
typedef namespace_info_t* (*get_namespace_info_f) (GError **error);

/**
 * Get the rules path from conscience
 * @param ns
 * @param srvtype
 * @param path
 * @param err
 * @return
 */
gboolean namespace_get_rules_path(const gchar *ns, const gchar *srvtype,
		gchar **path, GError **err);

/**
 * Get namespace rules
 * @param ns
 * @param srvtype
 * @param err
 * @return
 */
GByteArray* namespace_get_rules(const gchar *ns, const gchar *srvtype,
		GError **err);

/**
 * @param ns
 * @param what
 * @param how
 * @return NULL if the NS was not found or the key not defined for the NS
 */
gchar* gridcluster_get_config(const gchar *ns, const gchar *what, gint how);


/** List all the configuration variables locally set.
 * @return
 */
GHashTable* gridcluster_parse_config(void);


/** List all the namespaces locally known
 * @return
 */
gchar** gridcluster_list_ns(void);


/** Returns the services update's configuration when the Load-Balancing
 * is performed by a servce of type srvtype for each namespace and virtual namespace.
 *
 * Thus 'srvtype' is not the service type that is being load-balanced, but
 * the service doing the LB.
 *
 * @param nsinfo
 * @param srvtype
 * @return
 */
GHashTable* gridcluster_get_service_update_policy(struct namespace_info_s *nsinfo,
		const gchar *srvtype);

/**
 *
 *
 *
 */
GHashTable* gridcluster_get_event_config(struct namespace_info_s *nsinfo,
		const gchar *srvtype);

/*!
 * @params nsinfo
 * @return
 */
gint64 gridcluster_get_container_max_versions(struct namespace_info_s *nsinfo);

struct grid_lbpool_s;

/*!
 * @param glp
 * @return NULL in case of successes
 */
GError* gridcluster_reload_lbpool(struct grid_lbpool_s *glp);

/*!
 * @param glp
 * @return
 */
GError* gridcluster_reconfigure_lbpool(struct grid_lbpool_s *glp);

/**
 * Get the delay before actually removing contents marked as deleted.
 *
 * @param nsinfo A pointer to the namespace infos
 * @return The delay in seconds, or -1 if disabled (never delete)
 */
gint64 gridcluster_get_keep_deleted_delay(struct namespace_info_s *nsinfo);

gchar* gridcluster_get_nsinfo_strvalue(struct namespace_info_s *nsinfo,
		const gchar *key, const gchar *def);

gint64 gridcluster_get_nsinfo_int64(struct namespace_info_s *nsinfo,
		const gchar* key, gint64 def);

/** @} */

#endif	/* _GRIDCLUSTER_H */
