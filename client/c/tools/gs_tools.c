#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.ls"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>

#include <metautils/lib/metautils.h>
#include "gs_tools.h"

char *optarg;
int flag_verbose = 0; // must be defined because of IGNORE_ARG macro

/**
 * Creates a new t_gs_tools_options initialized to zeroes.
 * @return a new t_gs_tools_options
 */
static t_gs_tools_options* _new_gs_tools_options()
{
	return g_malloc0(sizeof(t_gs_tools_options));
}

/**
 * Frees the given t_gs_tools_options.
 * @param options the t_gs_tools_options to be freed
 */
static void _free_gs_tools_options(t_gs_tools_options* options)
{
	g_free(options->meta0_url);
	g_free(options->container_name);
	g_free(options->user_metadata);
	g_free(options->sys_metadata);
	g_free(options->local_path);
	g_free(options->remote_path);
	g_free(options->base_dir);
	g_free(options->storage_policy);
	g_free(options->version);
	g_free(options->propkey);
	g_free(options->propvalue);
	g_free(options);
}

/**
 * Frees the given argument array.
 * @param hc_arg argument array to be freed
 */
static void _free_hc_arg(gchar **hc_arg)
{
	g_strfreev(hc_arg);
}
/**
 * This function generates the argument list suitable for hc command, from the
 * original arguments passed to gs_* command.
 * - The -v -h -q options are simply copied to the new argument list;
 * - The -k and -r option string are added to the argument list;
 * - Other non-option arguments are simply copied after all options;
 * @param p_hc_arg a pointer to the argument array to build
 * @param cmd hcdir command name
 * @param options the options parsed by parse_opt_generic
 * @param argc argument count
 * @param args argument array
 */
static void _make_hcdir_arg(gchar ***p_hc_arg, const char *cmd, t_gs_tools_options *options, int argc, char **args)
{
	gchar tmparg[128]; // holds NAMESPACE/CONTAINER
	gchar *cursor = &(tmparg[0]);
	gchar **hc_arg;
	gint i = 0, j = 0;
	const int nb_O_options = 10;

	memset(tmparg, 0, sizeof(tmparg));

	hc_arg = g_malloc0((argc + 2 ) * sizeof(gchar*));

	hc_arg[i++] = g_strdup("hcdir");

	hc_arg[i++] = g_strdup(cmd);

	if (options->flag_verbose)
		hc_arg[i++] = g_strdup("-v");
	if (options->flag_help)
		hc_arg[i++] = g_strdup("-h");
	if (options->flag_quiet)
		hc_arg[i++] = g_strdup("-q");

	if (options->meta0_url) {
		cursor = g_stpcpy(cursor, options->meta0_url);
	}
	if (options->container_name) {
		cursor = g_stpcpy(cursor, "/");
		cursor = g_stpcpy(cursor, options->container_name);
	}
	if (options->remote_path) {
		cursor = g_stpcpy(cursor, "/");
		cursor = g_stpcpy(cursor, options->remote_path);
	}
	if (options->version) {
		cursor = g_stpcpy(cursor, "?version=");
		cursor = g_stpcpy(cursor, options->version);
	}
	if (tmparg[0])
		hc_arg[i++] = g_strdup(tmparg);

	if (options->propkey) {
		hc_arg[i++] = g_strdup(options->propkey);
	}
	if (options->propvalue) {
		hc_arg[i++] = g_strdup(options->propvalue);
	}
	// all other arguments are copied
	while (i < argc + nb_O_options + 1 && args[j])
		hc_arg[i++] = g_strdup(args[j++]);

	// last element has to be NULL
	hc_arg[i++] = NULL;

	*p_hc_arg = hc_arg;
}

/**
 * This function generates the argument list suitable for hc command, from the
 * original arguments passed to gs_* command.
 *  - The -v -h -q options are simply copied to the new argument list;
 *  - The -s -F -f -X -a -u -S options are translated to their -O twin in hc world;
 *  - The -V option is prefixed with "?version=" and appended to URL;
 *  - The -k and -r option string are added to the argument list;
 *  - Other non-option arguments are simply copied after all options;
 *  - The -p option string is added as last argument.
 * @param p_hc_arg a pointer to the argument array to build
 * @param cmd hc command name
 * @param options the options parsed by parse_opt_generic
 * @param argc argument count
 * @param args argument array
 */
static void _make_hc_arg(gchar ***p_hc_arg, const char *cmd, t_gs_tools_options *options, int argc, char **args)
{
	gchar tmparg[128]; // holds NAMESPACE/CONTAINER
	gchar *cursor = &(tmparg[0]);
	gint i = 0, j = 0;
	gchar **hc_arg;
	const int nb_O_options = 10; // number of -O options available

	memset(tmparg, 0, sizeof(tmparg));

	// Allocate argc+nb_O_options+2 pointers in order to hold the trailing NULL and
	// the beginning "hc", and optionally the -O options (2 tokens: -O and OptionName, hence
	// we need 1 more element for each -O option).
	hc_arg = g_malloc0((argc + nb_O_options + 2) * sizeof(gchar*));

	// "hc" has to be the first element
	hc_arg[i++] = g_strdup("hc");

	// the command has to be the second element
	hc_arg[i++] = g_strdup(cmd);

	// handle flags
	if (options->flag_verbose)
		hc_arg[i++] = g_strdup("-v");
	if (options->flag_help)
		hc_arg[i++] = g_strdup("-h");
	if (options->flag_quiet)
		hc_arg[i++] = g_strdup("-q");
	if (options->flag_info) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strdup("ShowInfo=True");
	}
	if (options->flag_full_chunks) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strdup("GroupChunks=False");
	}
	if (options->flag_activate_versioning) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strdup_printf("ActivateVersioning=%"G_GINT64_FORMAT, options->versioning);
	}
	if (options->flag_force) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strdup("Force");
	}
	if (options->flag_cache) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strdup("Cache");
	}
	if (options->flag_auto_create) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strdup("Autocreate");
	}
	if (options->user_metadata) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strconcat("Metadata=", options->user_metadata, NULL);
	}
	if (options->storage_policy) {
		hc_arg[i++] = g_strdup("-O");
		hc_arg[i++] = g_strconcat("StoragePolicy=", options->storage_policy, NULL);
	}

	// if -m NAMESPACE -d CONTAINER -c CONTENT options are supplied,
	// generate NAMESPACE/CONTAINER/CONTENT
	if (options->meta0_url) {
		cursor = g_stpcpy(cursor, options->meta0_url);
	}
	if (options->container_name) {
		cursor = g_stpcpy(cursor, "/");
		cursor = g_stpcpy(cursor, options->container_name);
	}
	if (options->remote_path) {
		cursor = g_stpcpy(cursor, "/");
		cursor = g_stpcpy(cursor, options->remote_path);
	}
	if (options->version) {
		cursor = g_stpcpy(cursor, "?version=");
		cursor = g_stpcpy(cursor, options->version);
	}
	if (tmparg[0])
		hc_arg[i++] = g_strdup(tmparg);


	if (options->propkey) {
		hc_arg[i++] = g_strdup(options->propkey);
	}
	if (options->propvalue) {
		hc_arg[i++] = g_strdup(options->propvalue);
	}
	// all other arguments are copied
	while (i < argc + nb_O_options + 1 && args[j])
		hc_arg[i++] = g_strdup(args[j++]);

	// Set local_path as last argument
	if (options->local_path) {
		hc_arg[i++] = g_strdup(options->local_path);
	}

	// last element has to be NULL
	hc_arg[i++] = NULL;

	*p_hc_arg = hc_arg;
}

/**
 * This functions parses the given options and fills corresponding global
 * variables. All gs_* options are supported.
 * @param argc argument count
 * @param args argument array
 * @param options stores options values
 * @return 1
 */
static gint parse_opt_generic(int argc, char **args, t_gs_tools_options *options)
{
	int opt;

	g_assert(options);

	while ((opt = getopt(argc, args, "hfvqsXalFW:V:C:m:c:p:d:o:S:t:u:k:r:")) != -1) {
		switch (opt) {

		case 'h':
			options->flag_help = ~0;
			break;

		case 'f':
			options->flag_force = ~0;
			break;

		case 'v':
			options->flag_verbose++;
			flag_verbose++;
			break;

		case 'q':
			options->flag_quiet = ~0;
			break;

		case 'l':
			options->flag_info = ~0;
			break;

		case 'X':
			options->flag_cache = ~0;
			break;

		case 'a':
			options->flag_auto_create = ~0;
			break;

		case 'F':
			options->flag_full_chunks = ~0;
			break;

		case 'W':
			options->flag_activate_versioning = ~0;
			options->versioning = g_ascii_strtoll(optarg, NULL, 10);
			break;

		case 'V':
			/* version */
			IGNORE_ARG('V');
			g_free(options->version);
			options->version = g_strdup(optarg);
			break;

		case 'C':
			/* base directory */
			IGNORE_ARG('C');
			g_free(options->base_dir);
			options->base_dir = strdup(optarg);
			break;

		case 'm':
			/* meta0 url */
			IGNORE_ARG('m');
			g_free(options->meta0_url);
			options->meta0_url = g_strdup(optarg);
			break;

		case 'c':
			/* remote source path */
			IGNORE_ARG('c');
			g_free(options->remote_path);
			options->remote_path = strdup(optarg);
			break;

		case 'p':
			/* local output path */
			IGNORE_ARG('p');
			g_free(options->local_path);
			options->local_path = strdup(optarg);
			break;

		case 'd':
			/* container info */
			IGNORE_ARG('d');
			g_free(options->container_name);
			options->container_name = g_strdup(optarg);
			break;

		case 'o':
			options->offset = atoi(optarg);
			break;

		case 'k':
			/* property name */
			IGNORE_ARG('k');
			options->propkey = g_strdup(optarg);
			break;
		case 'r':
			/* property value */
			IGNORE_ARG('r');
			options->propvalue = g_strdup(optarg);
			break;

		case 'S':
			/* storage policy*/
			IGNORE_ARG('S');
			g_free (options->storage_policy);
			options->storage_policy = strdup (optarg);
			break;

		case 't':
			/* mime type */
			IGNORE_ARG('t');
			if (!options->sys_metadata)
				options->sys_metadata = g_string_new("");
			g_string_append_printf(options->sys_metadata, "mime-type=%s;", optarg);
			break;

		case 'u':
			/* user metadata */
			IGNORE_ARG('u');
			g_free(options->user_metadata);
			options->user_metadata = strdup(optarg);
			break;

		case '?':
		default:
			break;
		}
	}
	return 1;
}


static gboolean is_propcmd(const gchar *cmd) {
	if ( g_ascii_strcasecmp(cmd,"propget") == 0 ||
		g_ascii_strcasecmp(cmd,"propset") == 0 ||
		g_ascii_strcasecmp(cmd,"propdel") == 0 ) {
		return TRUE;
	}
	return FALSE;
}

/**
 * Calls the "hc" program with the given command and arguments.
 * @param cmd the command to be passed to hc
 * @param options the options parsed by parse_opt_generic
 * @param argc argument number
 * @param args argument array
 * @return 0 if no error is encountered, 1 if there is an error with generated arguments, -1 otherwise.
 */
static gint call_hc_command(const gchar *cmd, t_gs_tools_options *options, int argc, gchar **args)
{
	int rc = 0, status;
	pid_t pid;
	gchar **hc_arg = NULL;
	errno = 0;

	if ( is_propcmd(cmd) ) {
		if ( is_content_specified(options,args ) )
			_make_hc_arg(&hc_arg, cmd, options, argc, args);
		else
			_make_hcdir_arg(&hc_arg, cmd, options, argc, args);
	} else {
		_make_hc_arg(&hc_arg, cmd, options, argc, args);
	}

	// The execvp function does not return on successful execution.
	// In order to free hc_arg, we execute the command in a child process, and
	// wait for it to terminate. Then we can free hc_arg from the parent process.
	if (0 == (pid = fork())) {
		// execvp never returns unless an error occurs,
		// in which case the returned value is -1.
		rc = execvp(*hc_arg, hc_arg);
		GRID_ERROR("Error executing command: %s", strerror(errno));
	} else if (pid < 0) {
		GRID_ERROR("Error creating fork: %s", strerror(errno));
		rc = -1;
	} else {
		if (waitpid(pid, &status, 0) != pid) {
			GRID_ERROR("Error while waiting for child: [status %i] %s", status, strerror(errno));
			rc = -1;
		}
	}

	_free_hc_arg(hc_arg);

	return rc;
}

/**
 * This function determines whether a content name is specified in argument list,
 * either using -c option of with NAMESPACE/CONTAINER/CONTENT syntax.
 * @param gto the option structure
 * @param extra_args non-option arguments
 * @return TRUE if content name is specified
 */
extern gboolean is_content_specified(t_gs_tools_options *gto, gchar **extra_args)
{
	gboolean has_content_in_url = (NULL != get_content_name(*extra_args));
	gboolean has_content_in_options = gto && gto->remote_path;
	return has_content_in_options || has_content_in_url;
}


/**
 * This function returns the content name extracted from NAMESPACE/CONTAINER/CONTENTNAME
 * url.
 * @param url the url to parse
 * @return a copy of the content name
 */
extern gchar* get_content_name(gchar *url)
{
	gchar *next_slash, *question_mark;
	if (url && *url) {
		next_slash = strchr(url, '/');
		if (next_slash && *(next_slash + 1)) {
			next_slash = strchr(next_slash + 1, '/');
			if (next_slash && *(next_slash + 1)) {
				if (NULL != (question_mark = strchr(next_slash, '?')))
					return g_strndup(next_slash + 1, question_mark - next_slash - 1);
				else
					return g_strdup(next_slash + 1);
			}
		}
	}
	return NULL;
}

/**
 * This function parses the given arguments to generate a new set of arguments
 * suitable for "hc" command. The main hc command is specified with cmd argument.
 * Last argument is a callback which prints usage message.
 * @param argc argument count
 * @param argv argument array
 * @param cmd main hc command
 * @param helpcb help callback
 * @return 0 if no error is encountered, -1 otherwise.
 */
extern gint gs_tools_main(int argc, gchar **argv, const gchar *cmd, void (*helpcb)(void))
{
	return gs_tools_main_with_argument_check(argc, argv, cmd, helpcb, NULL);
}

/**
 * This function parses the given arguments to generate a new set of arguments
 * suitable for "hc" command. The generated arguments can be checked using the
 * given callback (last argument). The main hc command is specified with cmd argument.
 * The helpcb argument is a callback which prints usage message.
 * @param argc argument count
 * @param argv argument array
 * @param cmd main hc command
 * @param helpcb help callback
 * @param check_args callback used to check generated arguments (NULL if not needed).
 * @return 0 if no error is encountered, -1 otherwise.
 */
extern gint
gs_tools_main_with_argument_check(int argc, gchar **argv, const gchar *cmd,
		void (*helpcb)(void), gboolean (*check_args)(t_gs_tools_options*, gchar**))
{
	int rc = 0;

	/* TODO refactor with grid_common_main */
	if (!g_thread_supported ())
		g_thread_init (NULL);
	g_log_set_default_handler(logger_stderr, NULL);
	g_set_prgname(argv[0]);
	logger_init_level(GRID_LOGLVL_INFO);
	logger_reset_level();

	client_gscstat_init();
	t_gs_tools_options *gs_tools_options = _new_gs_tools_options();

	if (!parse_opt_generic(argc, argv, gs_tools_options)) {
		GRID_ERROR("Cannot parse options");
		rc = -1;
		goto gto_main_error;
	}

	if (argc == 1 || gs_tools_options->flag_help || (check_args && !check_args(gs_tools_options, argv + optind))) {
		if (helpcb)
			helpcb();
		rc = -1;
		goto gto_main_error;
	}

	rc = call_hc_command(cmd, gs_tools_options, argc, argv + optind);

gto_main_error:
	_free_gs_tools_options(gs_tools_options);
	client_gscstat_close();
	return rc;
}

void
client_gscstat_init(void)
{
	GError *e = NULL;
    if (0 == gscstat_initAndConfigureALLServices(&e))
		gscstat_tags_start(GSCSTAT_SERVICE_ALL, GSCSTAT_TAGS_REQPROCTIME);
	else {
		g_assert(e != NULL);
		GRID_ERROR("Statistics support not initiated : (%d) %s",
				e->code, e->message);
		g_clear_error(&e);
	}
}

void
client_gscstat_close(void)
{
	gscstat_tags_end(GSCSTAT_SERVICE_ALL, GSCSTAT_TAGS_REQPROCTIME);
	char* str = gscstat_dumpAllServices();
	if (str != NULL) {
		PRINT_DEBUG("processTimeService: \n%s", str);
		free(str);
	}
	gscstat_free();
}

