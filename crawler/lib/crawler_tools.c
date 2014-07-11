#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid.crawler.common"
#endif //G_LOG_DOMAIN


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>
#include <gmodule.h>

#include <metautils/lib/metautils.h>

#include "crawler_constants.h"
#include "crawler_tools.h"


void buildServiceName(char* svc_name, int max_size_svc_name, 
		char* prefix_name, char* action_name, int pid, gboolean bPrefixOnly)
{
	if (bPrefixOnly)
		g_snprintf(svc_name, max_size_svc_name, "%s_%s", prefix_name, action_name);
	else
		g_snprintf(svc_name, max_size_svc_name, "%s_%s_%d", prefix_name, action_name, pid);
}


char* getBusAddress(char* userdata)
{
	char* add = NULL;
	if (userdata != NULL) {
		add = g_malloc0(strlen(userdata)+10);
		strcpy(add, userdata);
		GRID_DEBUG("dbus_daemon address:\"%s\"", add);        
	}
	GRID_DEBUG("dbus_daemon address:\"%s\"", ((add)?add:"(null)"));
	return add;
}




gchar* g_substr(const gchar* string, guint32 start_pos, guint32 end_pos)
{
	gsize len;
	gchar* output = NULL;

	if (start_pos >= strlen(string))
		return NULL;

	if (end_pos > strlen(string))
		len = strlen(string) - start_pos;
	else
		len = end_pos - start_pos;

	output = g_malloc0(len + 1);
	if (NULL == output)
		return NULL;

	return g_utf8_strncpy(output, &string[start_pos], len);
}



guint64 get_child_value_uint64(GVariant* gv, int order)
{
	guint64 value = 0;
	GVariant* tmp = g_variant_get_child_value(gv, order);
	if (tmp) {
		value = g_variant_get_uint64(tmp);
		g_variant_unref(tmp);
	}
	return value;
}

GVariant* get_child_value_variant(GVariant* gv, int order)
{
	GVariant* value = NULL;

	GVariant* tmp = g_variant_get_child_value(gv, order);
	if (tmp) {
		value = g_variant_get_variant(tmp);
		g_variant_unref(tmp);
	}
	return  value;
}

int get_child_value_int(GVariant* gv, int order)
{
	int value = 0;

	GVariant* tmp = g_variant_get_child_value(gv, order);
	if (tmp) {
		value = g_variant_get_int32(tmp);
		g_variant_unref(tmp);
	}
	return value;
}


const gchar* get_child_value_string(GVariant* gv, int order)
{
	const gchar* value = NULL;

	GVariant* tmp = g_variant_get_child_value(gv, order);
	if (tmp) {
		value = g_variant_get_string(tmp, NULL);
		g_variant_unref(tmp);
	}
	return value;
}


void get_child_value_strv(GVariant* gv, int order, gchar*** value)
{
	GVariant* tmp = g_variant_get_child_value(gv, order);
	if (tmp) {
		*value = (gchar**)g_variant_dup_strv(tmp, NULL);
		g_variant_unref(tmp);
	} else *value = NULL;
}



/* Returned argv value must be freed with g_free() */
int disassemble_context_occur_argc_argv_uid(GVariant* gv_glued, guint64* context_id,
		GVariant** gv_src, int* argc, char*** argv, guint64* service_uid)
{
	GVariantType* gvt = g_variant_type_new(gvariant_action_param_type_string);
	if (NULL == gv_glued || FALSE == g_variant_is_of_type(gv_glued, gvt)) {
		g_variant_type_free(gvt);

		return EXIT_FAILURE;
	}
	g_variant_type_free(gvt);

	*context_id  = get_child_value_uint64( gv_glued, 0);
	*gv_src      = get_child_value_variant(gv_glued, 1);
	*argc        = get_child_value_int(    gv_glued, 2);
	get_child_value_strv(   gv_glued, 3, argv);
	*service_uid = get_child_value_uint64( gv_glued, 4);

	return EXIT_SUCCESS;
}


GVariant* assemble_context_occur_argc_argv_uid(GVariant** b, guint64 context_id, GVariant* gv, int argc,
		char** argv, guint64 service_uid)
{
	GVariantBuilder* argv_builder = NULL;
	GVariant* ret = NULL;
	int i;

	if (NULL == gv || NULL == argv)
		return NULL;


	argv_builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	for (i = 0; (argv[i]); i++)
		g_variant_builder_add(argv_builder, "s", argv[i]);


	ret = g_variant_new(gvariant_action_param_type_string, context_id, gv, argc,
			argv_builder, service_uid);

	g_variant_builder_unref(argv_builder);

	*b = ret;
	return ret;
}



gchar* get_argv_value(int argc, char** argv, gchar* module_name, gchar* variable_name)
{
	int i;
	gchar* temp = NULL;
	gchar* temp2 = NULL;
	gchar* ret = NULL;

	temp = g_strconcat(opt_indicator, module_name, opt_separator, variable_name,
			opt_affectation, NULL);
	for (i = 0;(NULL == ret) && (i < argc); i++) {
		/* Testing the minimal length of the option */
		if (strlen(temp) + 1 > strlen(argv[i])) {
			continue;
		}
		/* ------- */

		temp2 = g_substr(argv[i], 0, strlen(temp));
		if (!g_strcmp0(temp, temp2))
			ret = g_substr(argv[i], strlen(temp), strlen(argv[i]));
		g_free(temp2);
	}
	g_free(temp);
	return ret;
}

gboolean chunk_path_is_valid(const gchar* file_path)
{
	gboolean ret = FALSE;
	guint count = 0;
	const gchar *s;
	register gchar c;
	gchar* f_basename = g_path_get_basename(file_path);

	for (s=f_basename; (c = *s) ;s++) {
		if (c == '.')
			break;
		if (FALSE == g_ascii_isxdigit(c))
			goto clean_up;
		if (++count > 64)
			goto clean_up;
	}

	if (count != 64)
		goto clean_up;

	if (c == '.') {
		// chunks ending with ".pending" and older than 24h
		// are considered as valid
		if (0 == g_strcmp0(s, ".pending")) {
			time_t now = time(NULL);
			struct stat chunk_stat;
			errno = 0;
			if (0 == stat(file_path, &chunk_stat))
				ret = (now - chunk_stat.st_mtime) > 24*60*60;
			else
				GRID_ERROR("Cannot stat file [%s] (%s)",
						file_path, strerror(errno));
		}
	} else {
		ret = (c == '\0');
	}

clean_up:
	g_free(f_basename);
	return ret;
}

gboolean container_path_is_valid(const gchar* file_path)
{
	if (FALSE == chunk_path_is_valid(file_path))
		return FALSE;

	FILE* file_pointer = NULL;
	int str_cmp = -1;
	gchar my_header[16] = "";

	file_pointer = fopen(file_path, "r");
	if (NULL != file_pointer) {
		if (NULL != fgets(my_header, 16, file_pointer))
			str_cmp = g_strcmp0(my_header, "SQLite format 3");

		fclose (file_pointer);
	}

	return (!str_cmp);
}

int move_file(const char* source_file_path, const char* destination_file_path,
		gboolean delete_after)
{
	FILE* source_file_pointer;
	FILE* destination_file_pointer;
	char buffer[SHORT_BUFFER_SIZE];
	int read_bytes_number;

	source_file_pointer = fopen(source_file_path, "rb");
	if (source_file_pointer == NULL) {
		return EXIT_FAILURE;
	}

	destination_file_pointer = fopen(destination_file_path, "wb");
	if (destination_file_pointer == NULL) {
		fclose(source_file_pointer);
		return EXIT_FAILURE;
	}

	while ((read_bytes_number = fread(buffer, 1, SHORT_BUFFER_SIZE,
					source_file_pointer))) {
		fwrite(buffer, 1, read_bytes_number, destination_file_pointer);
	}

	fclose(destination_file_pointer);
	fclose(source_file_pointer);

	if (TRUE == delete_after)
		remove(source_file_path);

	return EXIT_SUCCESS;
}




void free_trip_lib_entry_points(struct trip_lib_entry_points* trip_ep)
{
	if (NULL != trip_ep) {
		if (NULL != trip_ep->lib_ref)
			g_module_close(trip_ep->lib_ref);
		g_free(trip_ep);
	}
}


/**
 *  * plugin_path: path+filename of libtrip_xx.so
 *   */
struct trip_lib_entry_points* load_trip_library(char* path, char* trip_library_name)
{
	gchar* plugin_path = NULL;
	struct trip_lib_entry_points* ret = NULL;

	if (NULL == trip_library_name)
		return NULL;

	if (path && strlen(path)>0 )
		plugin_path = g_strconcat(path, G_DIR_SEPARATOR_S, "lib", trip_library_name, ".so", NULL);
	else
		plugin_path = g_strconcat(TRIP_INSTALL_PATH, G_DIR_SEPARATOR_S, "lib", trip_library_name, ".so", NULL);

	ret = (struct trip_lib_entry_points*)g_malloc0(sizeof(struct trip_lib_entry_points));

	if (NULL == ret) {
		g_free(plugin_path);
		return NULL;
	}

	if (NULL == (ret->lib_ref = g_module_open(plugin_path, G_MODULE_BIND_LAZY))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_start", (void**)&(ret->trip_start))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_next", (void**)&(ret->trip_next))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_end", (void**)&(ret->trip_end))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}


	if (!g_module_symbol(ret->lib_ref, "trip_progress", (void**)&(ret->trip_progress))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}


	g_free(plugin_path);
	return ret;
}



