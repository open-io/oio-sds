/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CONFIG_H
#define CONFIG_H

/**
 * @defgroup integrity_loop_main_config Config
 * @ingroup integrity_loop_main
 * @{
 */

#include "check.h"

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
