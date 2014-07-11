#ifndef  __SRV_INTERNAL_ALERTS_H__
# define __SRV_INTERNAL_ALERTS_H__

/**
 * Used upon thread starvation
 */
# ifndef  ALERTID_SRV_THREADS
#  define ALERTID_SRV_THREADS "srv.threads"
# endif

/**
 * Default value for the higher bound of the alerting
 * frequency.
 */
# ifndef  DEFAULT_ALERT_PERIOD
#  define DEFAULT_ALERT_PERIOD 30
# endif

#endif /*__SRV_INTERNAL_ALERTS_H__*/
