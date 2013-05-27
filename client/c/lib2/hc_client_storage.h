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

#ifndef HC_CLIENT_STORAGE__H
# define HC_CLIENT_STORAGE__H 1

struct hc_input_s
{
	gpointer hook_data;
	int (*hook)(gpointer hook_data, guint8 *buf, gsize *bufsize);
};

struct hc_upload_s {
	gint64 size;
	const gchar *policy_name;
	struct hc_input_s input;
};

struct hc_output_s
{
	gpointer hook_data;
	int (*hook)(gpointer hook_data, const guint8 *buf, gsize bufsize);
};

struct hc_download_s
{
	gint64 offset;
	gint64 size;
	struct hc_output_s output;
};

/* forward declaration */
struct hc_url_s;
struct hc_resolver_s;

/* Hidden type */
struct hc_client_s;

/**
 * Creates a hc_client structure associated to the given resolver.
 *
 * @param resolver
 * @return
 */
struct hc_client_s* hc_client_create(struct hc_resolver_s *resolver);

/**
 *
 */
void hc_client_destroy(struct hc_client_s *hc);

/**
 * @param hc
 * @param u
 * @return 
 */
GError* hc_client_storage_delete_url(struct hc_client_s *hc, struct hc_url_s *u);

/**
 * @param hc
 * @param u
 * @return 
 */
GError* hc_client_storage_list_url(struct hc_client_s *hc, struct hc_url_s *u, GSList **result);

/**
 * @param hc
 * @param u
 * @return 
 */
GError* hc_client_storage_has_url(struct hc_client_s *hc, struct hc_url_s *u);

/**
 * @param hc
 * @param u
 * @param in
 * @return 
 */
GError* hc_client_storage_put_url(struct hc_client_s *hc, struct hc_url_s *u,
		struct hc_upload_s *in);

/**
 * @param hc
 * @param u
 * @return 
 */
GError* hc_client_storage_get_url(struct hc_client_s *hc, struct hc_url_s *u,
		struct hc_download_s *out);

#endif
