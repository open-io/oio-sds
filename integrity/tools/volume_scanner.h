/**
 * @file volume_scanner.h
 *
 * Parse the volume to find files and execute the given callback on each of them
 */

#ifndef VOLUME_SCANNER_H
#define VOLUME_SCANNER_H

/**
 * @defgroup integrity_loop_lib_volume_scanner Filesystem Scanner
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>

enum scanner_traversal_e {
	SCAN_ABORT,
	SCAN_STOP_BRANCH,
	SCAN_CONTINUE,
	SCAN_STOP_ALL
};

/**
 * @param dir_path
 * @param depth
 * @param data
 * @return FALSE if the run cannot continue, a TRUE value if it can go further
 */
typedef enum scanner_traversal_e (*scanner_dir_notifier_f) (const gchar *path, guint depth, void *data);

typedef enum scanner_traversal_e (*scanner_file_notifier_f) (const gchar *file_path, void *data, struct rules_motor_env_s** motor);

typedef gboolean (*scanner_file_matcher_f) (const gchar *dirname, const gchar *basename, void *data);

typedef enum scanner_traversal_e (*scanner_error_notifier_f) (const gchar *dir, GError *error, void *data);

/**
 * Struct to store informations used to scan a volume
 */
struct volume_scanning_info_s
{
	gchar *volume_path;	/*!< The full path to the volume */
	scanner_file_matcher_f file_match;	/*!<  */
	scanner_file_notifier_f file_action;	/*!< The function to call on each found file */
	scanner_dir_notifier_f dir_enter;	/*!< The volume traversal enters a new directory */
	scanner_dir_notifier_f dir_exit;	/*!<  */
	scanner_error_notifier_f error;
	void *callback_data;	/*!< Some user data to pass to the callback */
	long sleep_time;	/*!< The time to sleep between each callback execution in millisecond */
};

/**
 * Parse the volume to find files and execute the given callback on each of them
 *
 * @param scanning_info an instance of struct volume_scanning_info_s
 * @param motor
 *
 * - Go through the volume, looking for files
 * - Try to match found files against glob pattern
 * - Execute the callback given in scanning_info on each matching file
 * - Log error message in case the callback returned FALSE
 * - Wait for the given sleep time before processing the next file
 *
 * @test Test arguments
 *	- Execute with NULL pointer args
 * @test Test execution
 *	- Create a fake fs tree with some files
 *	- Execute function with '*' glob and check that all files where matched
 *	- Execute function with a glob that shouldn't match any file and check that none where found
 */
void scan_volume(struct volume_scanning_info_s* scanning_info, struct rules_motor_env_s** motor);

/** @} */


#endif /* VOLUME_SCANNER_H */
