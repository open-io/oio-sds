#ifndef __CONSCIENCE_ALERTS_H__
# define __CONSCIENCE_ALERTS_H__


#ifndef ALERTID_DOWN_META1
# define ALERTID_SCORE0_META1 "conscience.meta1.down"
#endif

#ifndef ALERTID_SCORE0_META1
# define ALERTID_SCORE0_META1 "conscience.meta1.score"
#endif


#ifndef ALERTID_DOWN_META2
# define ALERTID_SCORE0_META2 "conscience.meta2.down"
#endif

#ifndef ALERTID_SCORE0_META2
# define ALERTID_SCORE0_META2 "conscience.meta2.score"
#endif


#ifndef ALERTID_DOWN_RAWX
# define ALERTID_SCORE0_RAWX "conscience.rawx.down"
#endif

#ifndef ALERTID_SCORE0_RAWX
# define ALERTID_SCORE0_RAWX "conscience.rawx.score"
#endif


/**
 * 
 */
#ifndef ALERTID_BROKEN_META1
# define ALERTID_BROKEN_META1 "conscience.meta1.broken"
#endif

/**
 * 
 */
#ifndef ALERTID_BROKEN_META2
# define ALERTID_BROKEN_META2 "conscience.meta2.broken"
#endif

/**
 * Minimal (integer) number of broken containers in the 
 * same META2 to send an alert of a broken META2
 */
#ifndef ALERT_THRESHOLD_BRKM2
# define ALERT_THRESHOLD_BRKM2 256
#endif

/**
 * Minimal (integer) number of seconds between two alerts
 * of broken META2
 */
#ifndef ALERT_FREQUENCY_BRKM2
# define ALERT_FREQUENCY_BRKM2 300
#endif

#endif
