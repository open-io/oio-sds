/*
OpenIO SDS cluster conscience
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__cluster__module__alerting_h
# define OIO_SDS__cluster__module__alerting_h 1

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

#endif /*OIO_SDS__cluster__module__alerting_h*/