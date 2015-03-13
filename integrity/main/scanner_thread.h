/*
OpenIO SDS integrity
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__integrity__main__scanner_thread_h
# define OIO_SDS__integrity__main__scanner_thread_h 1

#include <integrity/lib/volume_scanner.h>
#include <integrity/main/config.h>

/**
 * @defgroup integrity_loop_main_scanner_thread Scanner Thread
 * @ingroup integrity_loop_main
 * @{
 */

/**
 * The scanning_info filler callback prototype
 *
 * @param scanning_info a preallocated volume_scanning_info_s to fill
 * @param service_info a service_info_t
 * @param config an integrity_loop config
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
typedef gboolean(*scanning_info_filler_f) (struct volume_scanning_info_s * scanning_info, service_info_t * service_info,
    struct integrity_loop_config_s * config, GError ** error);

/**
 * struct to store a filesystem scanner definition
 */
struct scanner_s
{
	gchar *matching_glob;	/*!< The glob the scanned files must match */
	GSList *workers;	/*!< The list of scan_worker_s to execute on each scanned files */
};

/**
 * struct to store a treatment to apply to a scanned file
 */
struct scan_worker_s
{
	scanning_info_filler_f scanning_info_filler;	/*!< The callback to fill the scanning_info */
};

/**
 * Initialize the scanner thread
 */
void init_scanning_thread();

/**
 * Register a new scanning callback for a given service type
 *
 * @param service_type the service type
 * @param worker a scan_worker_s describing the treament to apply to scanned files
 * @error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean register_scanning_callback(const gchar * service_type, struct scan_worker_s *worker, GError ** error);

/**
 * Start the volume scanner thread
 *
 * @param config the integrity loop config
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean start_scanner_thread(struct integrity_loop_config_s *config, GError ** error);

/** @} */

#endif /*OIO_SDS__integrity__main__scanner_thread_h*/