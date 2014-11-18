#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.loggers"
#endif

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "metautils.h"

static int syslog_opened = 0;

gchar syslog_id[256] = "";

int main_log_level_default = 0x7F;

int main_log_level = 0x7F;

int main_log_flags = LOG_FLAG_TRIM_DOMAIN
		| LOG_FLAG_PURIFY | LOG_FLAG_COLUMNIZE;

time_t main_log_level_update = 0;

inline guint16
compute_thread_id(GThread *thread)
{
	union {
		void *p;
		guint16 u[4];
	} bulk;
	memset(&bulk, 0, sizeof(bulk));
	bulk.p = thread;
	return (bulk.u[0] ^ bulk.u[1]) ^ (bulk.u[2] ^ bulk.u[3]);
}

static inline guint16
get_thread_id(void)
{
	return compute_thread_id(g_thread_self());
}

static inline const gchar*
glvl_to_str(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return "ERR";
		case G_LOG_LEVEL_CRITICAL:
			return "CRI";
		case G_LOG_LEVEL_WARNING:
			return "WRN";
		case G_LOG_LEVEL_MESSAGE:
			return "NOT";
		case G_LOG_LEVEL_INFO:
			return "INF";
		case G_LOG_LEVEL_DEBUG:
			return "DBG";
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return "ERR";
		case 2:
			return "WRN";
		case 4:
			return "NOT";
		case 8:
			return "INF";
		case 16:
			return "DBG";
		case 32:
			return "TR0";
		default:
			return "TR1";
	}
}

static inline int
glvl_to_lvl(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return LOG_CRIT;
		case G_LOG_LEVEL_CRITICAL:
			return LOG_ERR;
		case G_LOG_LEVEL_WARNING:
			return LOG_WARNING;
		case G_LOG_LEVEL_MESSAGE:
			return LOG_NOTICE;
		case G_LOG_LEVEL_INFO:
		case G_LOG_LEVEL_DEBUG:
			return LOG_INFO;
		default:
			break;
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return LOG_ERR;
		case 2:
			return LOG_WARNING;
		case 4:
			return LOG_NOTICE;
		case 8:
			return LOG_INFO;
		default:
			return LOG_DEBUG;
	}
}

static inline int
get_facility(const gchar *domain)
{
	return (domain && *domain == 'a' && !g_ascii_strcasecmp(domain, "access"))
		? LOG_LOCAL1 : LOG_LOCAL0;
}

#define REAL_LEVEL(L)   (guint32)((L) >> G_LOG_LEVEL_USER_SHIFT)
#define ALLOWED_LEVEL() REAL_LEVEL(main_log_level)

static inline gboolean
glvl_allowed(register GLogLevelFlags lvl)
{
	return (lvl & 0x7F)
		|| (ALLOWED_LEVEL() >= REAL_LEVEL(lvl));
}

static inline void
_purify(register gchar *s)
{
	static volatile gboolean done = FALSE;
	static guint8 invalid[256];

	register gchar c;

	if (!done) {
		done = TRUE;
		invalid[(guint8)('\n')] = 1;
		invalid[(guint8)('\r')] = 1;
		invalid[(guint8)('\t')] = 1;
	}

	for (; (c=*s) ; s++) {
		if (invalid[(guint8)c])
			*s = ' ';
	}
	*(s-1) = '\n';
}

static inline void
_append_message(GString *gstr, const gchar *msg)
{
	if (!msg)
		return;

	// skip leading blanks
	for (; *msg && g_ascii_isspace(*msg) ;msg++) {}

	g_string_append(gstr, msg);
}

void
logger_noop(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	(void) log_domain;
	(void) log_level;
	(void) message;
	(void) user_data;
}

static void
_logger_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	(void) user_data;

	GString *gstr = g_string_new("");

	g_string_append_printf(gstr, "%d %04X", getpid(), get_thread_id());

	if (LOG_LOCAL1 == get_facility(log_domain)) {
		g_string_append(gstr, " access ");
		g_string_append(gstr, glvl_to_str(log_level));
	}
	else {
		if (!log_domain || !*log_domain)
			log_domain = "-";
		g_string_append(gstr, " log ");
		g_string_append(gstr, glvl_to_str(log_level));
		g_string_append_c(gstr, ' ');
		g_string_append(gstr, log_domain);
	}

	g_string_append_c(gstr, ' ');

	_append_message(gstr, message);

	syslog(get_facility(log_domain)|glvl_to_lvl(log_level), gstr->str);
	g_string_free(gstr, TRUE);
}

void
logger_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	if (!glvl_allowed(log_level))
		return;
	_logger_syslog(log_domain, log_level, message, user_data);
}

static void
_logger_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	static guint longest_prefix = 38;
	struct timeval tv;
	GString *gstr;

	(void) user_data;

	gstr = g_string_sized_new(256);
	gettimeofday(&tv, NULL);

	g_string_append_printf(gstr, "%ld.%03ld %d %04X ",
			tv.tv_sec, tv.tv_usec/1000,
			getpid(), get_thread_id());

	if (!log_domain || !*log_domain)
		log_domain = "-";

	if (LOG_LOCAL1 == get_facility(log_domain)) {
		g_string_append_printf(gstr, "acc %s ", glvl_to_str(log_level));
	} else {
		g_string_append_printf(gstr, "log %s ", glvl_to_str(log_level));

		/* print the domain */
		if (!(main_log_flags & LOG_FLAG_TRIM_DOMAIN))
			g_string_append(gstr, log_domain);
		else {
			const gchar *p = log_domain;
			while (p && *p) {
				g_string_append_c(gstr, *p);
				p = strchr(p, '.');
				if (p) {
					g_string_append_c(gstr, '.');
					p ++;
				}
			}
		}
	}

	/* prefix done, print a separator */
	if (main_log_flags & LOG_FLAG_COLUMNIZE) {
		longest_prefix = MAX(gstr->len+1,longest_prefix);
		do {
			g_string_append_c(gstr, ' ');
		} while (gstr->len < longest_prefix);
	}
	else
		g_string_append_c(gstr, ' ');

	/* now append the message */
	_append_message(gstr, message);
	g_string_append_c(gstr, '\n');

	if (main_log_flags & LOG_FLAG_PURIFY)
		_purify(gstr->str);

	/* send the buffer */
	fwrite(gstr->str, gstr->len, 1, stderr);
	g_string_free(gstr, TRUE);
}

void
logger_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	if (!glvl_allowed(log_level))
		return;
	_logger_stderr(log_domain, log_level, message, user_data);
}


void
logger_verbose(void)
{
	main_log_level = (main_log_level*2)+1;
	main_log_level_update = time(0);
}

void
logger_verbose_default(void)
{
	main_log_level_default = (main_log_level_default * 2) + 1;
	main_log_level = main_log_level_default;
	main_log_level_update = time(0);
}

void
logger_init_level(int l)
{
	main_log_level_default = main_log_level = (l?(l|0x7F):0);
	main_log_level_update = time(0);
}

void
logger_init_level_from_env(const gchar *k)
{
	const gchar *v = g_getenv(k);
	if (v) {
		switch (g_ascii_toupper(*v)) {
			case 'T':
				logger_init_level(GRID_LOGLVL_TRACE2);
				return;
			case 'D':
				logger_init_level(GRID_LOGLVL_DEBUG);
				return;
			case 'I':
				logger_init_level(GRID_LOGLVL_INFO);
				return;
			case 'N':
				logger_init_level(GRID_LOGLVL_NOTICE);
				return;
			case 'W':
				logger_init_level(GRID_LOGLVL_WARN);
				return;
			case 'E':
				logger_init_level(GRID_LOGLVL_ERROR);
				return;
		}
	}
}

void
logger_reset_level(void)
{
	main_log_level = main_log_level_default;
}

void
logger_quiet(void)
{
	logger_init_level(0);
}

int
log4c_init(void)
{
	gchar path[512];

	main_log_level = main_log_level_default = GRID_LOGLVL_INFO;
	g_log_set_default_handler(logger_stderr, NULL);

	g_snprintf(path, sizeof(path), "/etc/log4crc");
	(void) log4c_load(path);

	g_snprintf(path, sizeof(path), "%s/.log4crc", g_get_home_dir());
	(void) log4c_load(path);

	g_snprintf(path, sizeof(path), "./.log4crc");
	(void) log4c_load(path);

	return 0;
}

int
log4c_fini(void)
{
	if (logger_syslog == g_log_set_default_handler(logger_stderr, NULL))
		closelog();
	return 0;
}

#include <expat.h>
#define ENUM2STR(W) case W: return strrchr(#W,'_')+1;

static const gchar *
xml_err2str(XML_Parser parser)
{
	switch (XML_GetErrorCode(parser)) {
		ENUM2STR(XML_ERROR_NONE);
		ENUM2STR(XML_ERROR_NO_MEMORY);
		ENUM2STR(XML_ERROR_SYNTAX);
		ENUM2STR(XML_ERROR_NO_ELEMENTS);
		ENUM2STR(XML_ERROR_INVALID_TOKEN);
		ENUM2STR(XML_ERROR_UNCLOSED_TOKEN);
		ENUM2STR(XML_ERROR_PARTIAL_CHAR);
		ENUM2STR(XML_ERROR_TAG_MISMATCH);
		ENUM2STR(XML_ERROR_DUPLICATE_ATTRIBUTE);
		ENUM2STR(XML_ERROR_JUNK_AFTER_DOC_ELEMENT);
		ENUM2STR(XML_ERROR_PARAM_ENTITY_REF);
		ENUM2STR(XML_ERROR_UNDEFINED_ENTITY);
		ENUM2STR(XML_ERROR_RECURSIVE_ENTITY_REF);
		ENUM2STR(XML_ERROR_ASYNC_ENTITY);
		ENUM2STR(XML_ERROR_BAD_CHAR_REF);
		ENUM2STR(XML_ERROR_BINARY_ENTITY_REF);
		ENUM2STR(XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF);
		ENUM2STR(XML_ERROR_MISPLACED_XML_PI);
		ENUM2STR(XML_ERROR_UNKNOWN_ENCODING);
		ENUM2STR(XML_ERROR_INCORRECT_ENCODING);
		ENUM2STR(XML_ERROR_UNCLOSED_CDATA_SECTION);
		ENUM2STR(XML_ERROR_EXTERNAL_ENTITY_HANDLING);
		ENUM2STR(XML_ERROR_NOT_STANDALONE);
		ENUM2STR(XML_ERROR_UNEXPECTED_STATE);
		ENUM2STR(XML_ERROR_ENTITY_DECLARED_IN_PE);
		ENUM2STR(XML_ERROR_FEATURE_REQUIRES_XML_DTD);
		ENUM2STR(XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING);
		default:
			return "???";
	}
}

static GError*
parse(const gchar *path, XML_Parser parser)
{
	gboolean rc;
	gsize len;
	gchar s[1024];
	FILE *in;
	GError *err = NULL;

	if (!(in = fopen(path, "r")))
		return NEWERROR(500, "fopen(%s) : (%d) %s", path, errno, strerror(errno));

	while (!feof(in) && !ferror(in)) {
		len = fread(s, 1, sizeof(s), in);
		if (len) {
			if (XML_STATUS_OK != (rc = XML_Parse(parser, s, len, 0))) {
				err = NEWERROR(500, "%s", xml_err2str(parser));
				break;
			}
		}
	}
	if (!err) {
		if (XML_STATUS_OK != (rc = XML_Parse(parser, "", 0, 1)))
			err = NEWERROR(500, "%s", xml_err2str(parser));
	}
	fclose(in);
	return err;
}

static const gchar *
_get_attr(const gchar **attrs, const gchar *an)
{
	if (!an || !*an)
		return "";
	for (; attrs && *attrs ;attrs++) {
		if (!g_ascii_strcasecmp(*attrs, an))
			return *(attrs+1);
	}
	return "";
}

static void
_set_default_priority(const char *what)
{
	if (!what || !*what) {
		logger_init_level(GRID_LOGLVL_INFO);
		return;
	}

	switch (*what) {
		case 'T':
		case 't':
			logger_init_level(GRID_LOGLVL_TRACE2);
			return;
		case 'D':
		case 'd':
			logger_init_level(GRID_LOGLVL_DEBUG);
			return;
		case 'I':
		case 'i':
			logger_init_level(GRID_LOGLVL_INFO);
			return;
		case 'N':
		case 'n':
			logger_init_level(GRID_LOGLVL_NOTICE);
			return;
		case 'W':
		case 'w':
			logger_init_level(GRID_LOGLVL_WARN);
			return;
		case 'E':
		case 'e':
			logger_init_level(GRID_LOGLVL_ERROR);
			return;
		default:
			logger_init_level(GRID_LOGLVL_INFO);
			return;
	}
}

static GLogLevelFlags
_priority_to_flags(const char *what)
{
	if (!what || !*what)
		return GRID_LOGLVL_INFO | 0X7F;

	switch (*what) {
		case 'T':
		case 't':
			return GRID_LOGLVL_TRACE | 0x7F;
		case 'D':
		case 'd':
			return GRID_LOGLVL_DEBUG | 0x7F;
		case 'I':
		case 'i':
			return GRID_LOGLVL_INFO | 0X7F;
		case 'N':
		case 'n':
			return GRID_LOGLVL_NOTICE | 0x7F;
		case 'W':
		case 'w':
			return GRID_LOGLVL_WARN | 0x7F;
		case 'E':
		case 'e':
			return GRID_LOGLVL_ERROR | 0x7F;

		default:
			return GRID_LOGLVL_INFO | 0x7F;
	}
}

static void
_stderr_open(void)
{
	g_strlcpy(syslog_id, "-", sizeof(syslog_id));
}

void
logger_syslog_open (void)
{
	if (syslog_opened)
		return;
	syslog_opened = 1;
	openlog(syslog_id, LOG_NDELAY, LOG_LOCAL0);
}

static void
_syslog_open(const char *tag)
{
	if (syslog_opened)
		return;
	memset(syslog_id, 0, sizeof(syslog_id));
	if (tag && *tag)
		g_strlcpy(syslog_id, tag, sizeof(syslog_id));
	else
		g_strlcpy(syslog_id, g_get_prgname(), sizeof(syslog_id));
	logger_syslog_open();
}

static gboolean
category_runner(gpointer k, gpointer v, gpointer u)
{
#define IS(n) !g_ascii_strcasecmp(app[0], n)
	const gchar *cat_name, **cat, **app;

	cat_name = k;
	cat = v;
	app = g_tree_lookup(u, cat[1]);
	//g_printerr("CAT[%s|%s] APP[%s|%s]\n", cat[0], cat[1], app[0], app[1]);

	(void) u;
	if (!g_ascii_strcasecmp(cat_name, "root")) {
		if (!app)
			g_log_set_default_handler(logger_noop, NULL);
		else {
			if (IS("syslog")) {
				_syslog_open(cat[1]);
				g_log_set_default_handler(logger_syslog, NULL);
			}
			else if (IS("stream") || IS("stderr")) {
				_stderr_open();
				g_log_set_default_handler(logger_stderr, NULL);
			}
			else
				g_log_set_default_handler(logger_noop, NULL);
		}
		_set_default_priority(cat[0]);
	}
	else {
		GLogLevelFlags flags = _priority_to_flags(cat[0]);

		if (!app)
			g_log_set_handler(cat_name, flags, logger_noop, NULL);
		else {
			if (IS("syslog")) {
				_syslog_open(cat[1]);
				g_log_set_handler(cat_name, flags, _logger_syslog, NULL);
			}
			else if (IS("stream") || IS("stderr")) {
				_stderr_open();
				g_log_set_handler(cat_name, flags, _logger_stderr, NULL);
			}
			else
				g_log_set_handler(cat_name, flags, logger_noop, NULL);
		}
	}
	return FALSE;
}

int
log4c_load(const char *path)
{
	GTree *tree_appenders, *tree_category;
	XML_Parser parser;

	gint cmp(gconstpointer p0, gconstpointer p1, gpointer u) {
		(void) u;
		return g_strcmp0(p0, p1);
	}
	void element_start(void *u, const XML_Char *n, const XML_Char **attrs) {
		gchar *tab[3] = {NULL,NULL,NULL};
		(void) u;
		switch (*n) {
			case 'C':
			case 'c':
				if (!g_ascii_strcasecmp(n, "category")) {
					tab[0] = g_strdup(_get_attr(attrs, "priority"));
					tab[1] = g_strdup(_get_attr(attrs, "appender"));
					g_tree_replace(tree_category, g_strdup(_get_attr(attrs, "name")), g_memdup(tab, sizeof(tab)));
				}
				return;
			case 'A':
			case 'a':
				if (!g_ascii_strcasecmp(n, "appender")) {
					tab[0] = g_strdup(_get_attr(attrs, "type"));
					tab[1] = g_strdup(_get_attr(attrs, "tag"));
					g_tree_replace(tree_appenders, g_strdup(_get_attr(attrs, "name")), g_memdup(tab, sizeof(tab)));
				}
				return;
		}
	}

	if (!path || !*path)
		return 0;

	DEBUG("Loading pseudo-log4c configuration from [%s]", path);

	tree_appenders = g_tree_new_full(cmp, NULL, g_free, (GDestroyNotify)g_strfreev);
	tree_category = g_tree_new_full(cmp, NULL, g_free, (GDestroyNotify)g_strfreev);
	parser = XML_ParserCreate(NULL);

	XML_SetUserData(parser, NULL);
	XML_SetStartElementHandler(parser, element_start);
	GError *err = parse(path, parser);

	XML_ParserReset(parser, NULL);
	XML_ParserFree(parser);

	g_tree_foreach(tree_category, category_runner, tree_appenders);

	g_tree_destroy(tree_category);
	g_tree_destroy(tree_appenders);

	if (!err)
		return 0;
	DEBUG("LOG4C configuration error : (%d) %s", err->code, err->message);
	g_clear_error(&err);
	return 1;
}

