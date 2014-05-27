#ifndef _AGENT_H
# define _AGENT_H

# include <sys/types.h>
# include <unistd.h>

# include <metautils/lib/metatypes.h>
# include <cluster/events/gridcluster_eventhandler.h>
# include <cluster/agent/gridagent.h>

# define IS_FORKED_AGENT (agent_type!=PT_REQ)
# define GS_AGENT_SPOOLDIR "/GRID/common/spool"

#ifndef GS_CONFIG_EVENT_DELAY
# define GS_CONFIG_EVENT_DELAY "event_delay"
#endif

#ifndef GS_CONFIG_EVENT_REFRESH
# define GS_CONFIG_EVENT_REFRESH "event_refresh"
#endif

#ifndef GS_CONFIG_NSINFO_REFRESH
# define GS_CONFIG_NSINFO_REFRESH "nsinfo_refresh"
#endif

# ifdef HAVE_EXTRA_DEBUG
#  define TRACE_POSITION() TRACE("At %s (%s %d)", __FUNCTION__, __FILE__, __LINE__)
# else
#  define TRACE_POSITION()
# endif

# ifndef DEFAULT_TIMEOUT_KILL
#  define DEFAULT_TIMEOUT_KILL 5L
# endif

enum process_type_e {PT_SUPERV, PT_EVT, PT_REQ};

/*One directory for each queue*/
struct event_queue_set_s {
	gchar dir_incoming[SPOOL_DIRNAME_LENGTH + LIMIT_LENGTH_NSNAME + sizeof(SUFFIX_SPOOL_INCOMING)];
	gchar dir_pending[SPOOL_DIRNAME_LENGTH + LIMIT_LENGTH_NSNAME + sizeof(SUFFIX_SPOOL_PENDING)];
	gchar dir_trash[SPOOL_DIRNAME_LENGTH + LIMIT_LENGTH_NSNAME + sizeof(SUFFIX_SPOOL_TRASH)];
};

typedef struct namespace_data_s {
	
	char name[LIMIT_LENGTH_NSNAME];
	namespace_info_t ns_info;
	gboolean configured;
	struct conscience_s *conscience;
	GSList *list_broken;
	
	/*services locally registered*/
	GHashTable *local_services;/**< Maps (gchar*) to (struct service_info_s*)*/
	GHashTable *down_services;/**< Maps (gchar*) to (struct service_info_s*)*/

	/*Event data*/
	struct event_queue_set_s queues;
} namespace_data_t;

void free_agent_structures(void);

int parse_namespaces(GError ** error);

int is_agent_running(void);

const gchar* get_signame(int s);

/* ------------------------------------------------------------------------- */

/**
 * Run a supervisor agent that will fork a request-agent, 
 * event management children, a configuration child, and
 * the services children.
 */
int main_supervisor(void);

/**
 *
 */
int main_event(const gchar *ns_name);

/**
 *
 */
int main_reqagent(void);

/* --- GLOBALS ------------------------------------------------------------- */

extern enum process_type_e agent_type;
extern GHashTable *namespaces;

extern gboolean flag_check_services;
extern int period_check_services;

extern int period_get_ns;
extern int period_get_evtconfig;
extern int period_get_srvtype;
extern int period_get_srvlist;
extern int period_push_srvlist;

extern gboolean flag_manage_broken;
extern int period_push_broken;
extern int period_get_broken;

extern gchar str_opt_config[1024];
extern gchar str_opt_log[1024];

extern gboolean gridagent_blank_undefined_srvtags;

/* ------------------------------------------------------------------------- */

extern char xattr_event_timestamp[256];
extern time_t event_delay;
extern time_t events_refresh_delay;

extern int event_file_mode;
extern int event_directory_mode;
extern gboolean event_queue_cleaning_allowed;
extern gchar *path_configured_top_spool_dir;

extern guint max_events_actions_pending;
extern guint max_events_pending;

extern char event_enable_receive;
extern char event_enable_manage;

/* Helpers ----------------------------------------------------------------- */

/**
 * Returns the delayed configured for the given namespace.
 * The value is read in the namesapce options if it is present, or taken
 * from the default configuration in the gridagent configuration.
 */
time_t get_event_delay(namespace_data_t *ns_data);

#endif	/* _AGENT_H */
