#ifndef CONFIG_H
#define CONFIG_H

/**
 * @defgroup integrity_loop_main_config Config
 * @ingroup integrity_loop_main
 * @{
 */

#include <integrity/main/check.h>

/**
 * Struct to store the integrity loop configuration
 */
struct integrity_loop_config_s {
	guint nb_volume_scanner_thread;	/*!< The maximum number of simultaneous threads running volume scans */
	long chunk_crawler_sleep_time;	/*!< The time to sleep between each chunk crawling in ms */
	long chunk_checker_sleep_time;  /*!< The time to sleep between each chunk checking in ms */
};

/**
 * Load the integrity loop config
 *
 * @param config integrity_loop_config_s which will be allocated and filled with config
 * @param error
 *
 * @return TRUE or FALSE if an error occured
 */
gboolean load_config(struct integrity_loop_config_s** config, GError** error);

/** @} */

#endif	/* CONFIG_H */
