/**
 * @file scanner_thread.h
 * Thread managing volume scanning checkers
 */

#ifndef SCANNER_THREAD_H
#define SCANNER_THREAD_H

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
#endif /* SCANNER_THREAD_H */
