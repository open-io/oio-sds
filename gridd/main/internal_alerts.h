/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__gridd__main__internal_alerts_h
# define OIO_SDS__gridd__main__internal_alerts_h 1

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

#endif /*OIO_SDS__gridd__main__internal_alerts_h*/