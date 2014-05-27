/**
 * @file conscience.h
 */

#ifndef _CONSCIENCE_H
# define _CONSCIENCE_H

/**
 * @addtogroup gridcluster_backend
 * @{
 */

# include <metautils/lib/metatypes.h>

# include <cluster/conscience/conscience_broken_holder.h>
# include <cluster/conscience/conscience_srvtype.h>
# include <cluster/conscience/conscience_srv.h>
# include <cluster/events/gridcluster_events.h>
# include <cluster/events/gridcluster_eventhandler.h>

/**
 * Provide this value OR'ed in the conscience_srvtype_run_all() flags to
 * run all the service, even those who have expired.
 */
#define SRVTYPE_FLAG_INCLUDE_EXPIRED 0x00000001

/**
 * Provide this value OR'ed in the conscience_srvtype_run_all() flags to
 * call the callback function with a NULL service when all the services
 * have been run.
 */
#define SRVTYPE_FLAG_ADDITIONAL_CALL 0x00000002

/**
 */
#define SRVTYPE_FLAG_LOCK_ENABLE     0x00000004

/**
 */
#define SRVTYPE_FLAG_LOCK_WRITER     0x00000008

/** struct used in virtual_namespace_tree in conscience */
struct vns_info_s
{
	gchar *name;
	gint64 space_used;
	gint64 total_space_used;
	gint64 quota;
};

/**
 *
 */
struct conscience_s
{
	namespace_info_t ns_info;

	/*Data about the broken elements of a GridStorage */
	GStaticRecMutex srmut_brk;
	struct broken_holder_s *broken_elements;

	/*Data about the configuration elements sent to each agent */
	GStaticRWLock rwlock_srv;
	GHashTable *srvtypes;/**<Maps (gchar*) to (struct conscience_srvtype_s*)*/
	struct conscience_srvtype_s *default_srvtype;

	/* The raw textual form of the event handler configuration */
	gridcluster_event_handler_t *event_handler;

	GNode *virtual_namespace_tree;
};

/**  */
enum mode_e
{
	MODE_AUTOCREATE, /**<  */
	MODE_FALLBACK,   /**<  */
	MODE_STRICT      /**<  */
};

/* ------------------------------------------------------------------------- */

/**
 * @return
 */
struct conscience_s *conscience_create(void);

/**
 *
 * @param ns_name
 * @param error
 * @return
 */
struct conscience_s *conscience_create_named(const gchar *ns_name, GError **error);

/**
 *
 */
void conscience_destroy(struct conscience_s *conscience);

/* ------------------------------------------------------------------------- */

/**
 * @param conscience
 * @param error
 * @param type
 * @param mode
 * @param lock_mode
 * @return
 */
struct conscience_srvtype_s *conscience_get_locked_srvtype(
		struct conscience_s *conscience, GError ** error,
		const gchar * type, enum mode_e mode, char lock_mode);

/**
 *
 */
void conscience_release_locked_srvtype(struct conscience_srvtype_s *srvtype);

/**
 * @param conscience
 * @param lock_mode 'w','W','r','R'
 */
void conscience_lock_srvtypes(struct conscience_s *conscience, char lock_mode);

/**
 * Release the lock set on the conscience's broken elements storage, whatever
 * the rights acquired on it (read/write).
 *
 * @param conscience
 */
void conscience_unlock_srvtypes(struct conscience_s *conscience);

/**
 * @param conscience
 * @param lock_mode 'w','W','r','R'
 */
void conscience_lock_broken_elements(struct conscience_s *conscience, char lock_mode);

/**
 * Release the lock set on the conscience's broken elements storage, whatever
 * the rights acquired on it (read/write).
 *
 * @param conscience
 */
void conscience_unlock_broken_elements(struct conscience_s *conscience);

/* ------------------------------------------------------------------------- */


/**
 * @param conscience
 * @param error
 * @param type
 * @param mode
 * @return 
 */
struct conscience_srvtype_s *conscience_get_srvtype(struct conscience_s *conscience, GError ** error,
    const gchar * type, enum mode_e mode);

/**
 * @param conscience
 * @param type
 * @param err
 * @return 
 */
struct conscience_srvtype_s *conscience_init_srvtype(
		struct conscience_s *conscience, const gchar * type, GError ** err);

/**
 *
 * @param conscience
 * @result
 */
struct conscience_srvtype_s *conscience_get_default_srvtype(
		struct conscience_s *conscience);

/**
 *
 * @param conscience
 * @result
 */
const gchar *conscience_get_namespace(struct conscience_s *conscience);

/**
 *
 * @param conscience
 * @param error
 * @result
 */
GSList *conscience_get_srvtype_names(struct conscience_s *conscience,
		GError ** error);

/**
 * @param conscience
 * @param error
 * @param flags
 * @param names_array
 * @param callback
 * @param udata
 * @return TRUE if the iterations succeeded ffor all the given service types, FALSE
 * if any error occurs.
 */
gboolean conscience_run_srvtypes(struct conscience_s * conscience,
		GError **error, guint32 flags, gchar ** names_array,
		service_callback_f * callback, gpointer udata);

/** @} */

#endif /* _CONSCIENCE_H */
