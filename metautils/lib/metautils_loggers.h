/**
 * @file loggers.h
 * Functions to help configuring the GLib logging system. We defining user-level
 * custom logging level, output layout, etc.
 */
#ifndef LOGGERS_H
# define LOGGERS_H 1

# include <glib.h>


/**
 * @defgroup metautils_loggers Logging V2 
 * @ingroup metautils_utils
 * @{
 */

# define GRID_LOGLVL_TRACE2 (64 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_TRACE  (32 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_DEBUG  (16 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_INFO   (8  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_NOTICE (4  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_WARN   (2  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_ERROR  (1  << G_LOG_LEVEL_USER_SHIFT)

/* enablers */
# ifdef HAVE_EXTRA_DEBUG
#  define GRID_TRACE2_ENABLED() (1)
#  define      TRACE2_ENABLED() (1)
#  define GRID_TRACE_ENABLED()  (1)
#  define      TRACE_ENABLED()  (1)
# else
#  define GRID_TRACE2_ENABLED() (0)
#  define      TRACE2_ENABLED() (0)
#  define GRID_TRACE_ENABLED()  (0)
#  define      TRACE_ENABLED()  (0)
# endif

# define GRID_DEBUG_ENABLED()  (main_log_level > GRID_LOGLVL_DEBUG)
# define GRID_INFO_ENABLED()   (main_log_level > GRID_LOGLVL_INFO)
# define GRID_NOTICE_ENABLED() (main_log_level > GRID_LOGLVL_NOTICE)
# define GRID_WARN_ENABLED()   (main_log_level > GRID_LOGLVL_WARN)
# define GRID_ERROR_ENABLED()  (main_log_level > 0)

# define DEBUG_ENABLED()       GRID_DEBUG_ENABLED()
# define INFO_ENABLED()        GRID_INFO_ENABLED()
# define NOTICE_ENABLED()      GRID_NOTICE_ENABLED()
# define WARN_ENABLED()        GRID_WARN_ENABLED()
# define ERROR_ENABLED()       GRID_ERROR_ENABLED()

/* new macros */
# ifdef HAVE_EXTRA_DEBUG
#  define GRID_TRACE2(FMT,...) g_log(G_LOG_DOMAIN, GRID_LOGLVL_TRACE2, FMT, ##__VA_ARGS__)
#  define GRID_TRACE(FMT,...)  g_log(G_LOG_DOMAIN, GRID_LOGLVL_TRACE, FMT, ##__VA_ARGS__)
# else
#  define GRID_TRACE2(FMT,...)
#  define GRID_TRACE(FMT,...)
# endif
# define GRID_LOG(LEVEL,FMT,...)   g_log(G_LOG_DOMAIN, LEVEL << G_LOG_LEVEL_USER_SHIFT, FMT, ##__VA_ARGS__)
# define GRID_DEBUG(FMT,...)   g_log(G_LOG_DOMAIN, GRID_LOGLVL_DEBUG, FMT, ##__VA_ARGS__)
# define GRID_INFO(FMT,...)    g_log(G_LOG_DOMAIN, GRID_LOGLVL_INFO, FMT, ##__VA_ARGS__)
# define GRID_NOTICE(FMT,...)  g_log(G_LOG_DOMAIN, GRID_LOGLVL_NOTICE, FMT, ##__VA_ARGS__)
# define GRID_WARN(FMT,...)    g_log(G_LOG_DOMAIN, GRID_LOGLVL_WARN, FMT, ##__VA_ARGS__)
# define GRID_ERROR(FMT,...)   g_log(G_LOG_DOMAIN, GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)

/* old macros */
# ifdef HAVE_EXTRA_DEBUG
#  define TRACE2(FMT,...) g_log(G_LOG_DOMAIN, GRID_LOGLVL_TRACE2, FMT, ##__VA_ARGS__)
#  define TRACE(FMT,...)  g_log(G_LOG_DOMAIN, GRID_LOGLVL_TRACE, FMT, ##__VA_ARGS__)
# else
#  define TRACE2(FMT,...)
#  define TRACE(FMT,...)
# endif
# define DEBUG(FMT,...)   g_log(G_LOG_DOMAIN, GRID_LOGLVL_DEBUG, FMT, ##__VA_ARGS__)
# define INFO(FMT,...)    g_log(G_LOG_DOMAIN, GRID_LOGLVL_INFO, FMT, ##__VA_ARGS__)
# define NOTICE(FMT,...)  g_log(G_LOG_DOMAIN, GRID_LOGLVL_NOTICE, FMT, ##__VA_ARGS__)
# define WARN(FMT,...)    g_log(G_LOG_DOMAIN, GRID_LOGLVL_WARN, FMT, ##__VA_ARGS__)
# define ERROR(FMT,...)   g_log(G_LOG_DOMAIN, GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)
# define FATAL(FMT,...)   g_log(G_LOG_DOMAIN, GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)
# define CRIT(FMT,...)    g_log(G_LOG_DOMAIN, GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)
# define ALERT(FMT,...)   g_log(G_LOG_DOMAIN, GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)

/* domain macros */
# ifdef HAVE_EXTRA_DEBUG
#  define TRACE2_DOMAIN(D,FMT,...) g_log((D), GRID_LOGLVL_TRACE2, FMT, ##__VA_ARGS__)
#  define TRACE_DOMAIN(D,FMT,...)  g_log((D), GRID_LOGLVL_TRACE, FMT, ##__VA_ARGS__)
# else
#  define TRACE2_DOMAIN(D,FMT,...)
#  define TRACE_DOMAIN(D,FMT,...)
# endif
# define DEBUG_DOMAIN(D,FMT,...)   g_log((D), GRID_LOGLVL_DEBUG, FMT, ##__VA_ARGS__)
# define INFO_DOMAIN(D,FMT,...)    g_log((D), GRID_LOGLVL_INFO, FMT, ##__VA_ARGS__)
# define NOTICE_DOMAIN(D,FMT,...)  g_log((D), GRID_LOGLVL_NOTICE, FMT, ##__VA_ARGS__)
# define WARN_DOMAIN(D,FMT,...)    g_log((D), GRID_LOGLVL_WARN, FMT, ##__VA_ARGS__)
# define ERROR_DOMAIN(D,FMT,...)   g_log((D), GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)
# define FATAL_DOMAIN(D,FMT,...)   g_log((D), GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)
# define CRIT_DOMAIN(D,FMT,...)    g_log((D), GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)
# define ALERT_DOMAIN(D,FMT,...)   g_log((D), GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)

/**
 * Cruising debug level. 
 *
 * Should not be altered by the application after the program has started.
 */
extern int main_log_level_default;

/**
 * Current (transitional) debug level.
 *
 * May be altered by the application, signals, etc.
 */
extern int main_log_level;

/**
 * Number of seconds since Epoch when the debug level has been updated.
 */
extern time_t main_log_level_update;

/**
 * Should the logging system try to reduce the prefix of each line
 */
extern int main_log_flags;

extern gchar syslog_id[256];

#define LOG_FLAG_TRIM_DOMAIN 0x01
#define LOG_FLAG_PURIFY 0x02
#define LOG_FLAG_COLUMNIZE 0x04

/**
 * @return
 */
int log4c_init(void);

/**
 * @param path
 * @return
 */
int log4c_load(const char *path);

/**
 * @return 
 */
int log4c_fini(void);

/**
 *
 */
void logger_verbose(void);

/**
 *
 */
void logger_verbose_default(void);

/**
 *
 */
void logger_quiet(void);

/**
 *
 * @param
 */
void logger_init_level(int l);

void logger_init_level_from_env(const gchar *k);

/**
 *
 */
void logger_reset_level(void);

/** Writes the layed out message to stderr (not fd=2) with complete and
 * compact layout.
 *
 * @param log_domain
 * @param log_level
 * @param message
 * @param user_data
 */
void logger_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

/** Does nothing
 *
 * @param log_domain
 * @param log_level
 * @param message
 * @param user_data
 */
void logger_noop(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

/** Send the mesage though /dev/syslog, with simple layout
 * @param log_domain
 * @param log_level
 * @param message
 * @param user_data
 */
void logger_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

/* Activate syslog logging */
void logger_syslog_open (void);

guint16 compute_thread_id(GThread *thread);
/** @} */

#endif /* LOGGERS_H */
