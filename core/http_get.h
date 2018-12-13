/*
OpenIO SDS core library
Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__sdk__http_get_h
#define OIO_SDS__sdk__http_get_h 1

#ifdef __cplusplus
extern "C"
{
#endif

#include <glib.h>

#include "oio_sds.h"

/**
* Metachunk download handle.
*/
	struct http_get_s;

/**
* Chunk download handle.
*/
	struct http_get_req_s;

/**
 * The range to be fetched, relative to the start of the metachunk or chunk.
 */
	struct http_get_range;

/**
 * Creates a meta-chunk download handle, patching the sizes and ranges to
 * fit them for EC.
 *
 * Computes the needed fragments for the given range in accordance to the EC
 * handle given and EC_SEGMENT_SIZE, then creates the meta-chunk download handle.
 *
 * @param mc_size The requested meta-chunk size
 * @param c_size The size of each chunk of this meta-chunk
 * @param req_range The range to be fetched, relative to the meta-chunk
 * 					(i.e. to the user data)
 * @param ec_k The K parameter of EC
 * @param ec_m The M parameter of EC
 * @param ec_handle The liberasurecode created for this download
 * @return A meta-chunk download handle
 */
	struct http_get_s *http_get_create_with_ec(gint64 mc_size, gint64 c_size,
			struct http_get_range *req_range, int ec_k, int ec_m,
			int ec_handle);

/**
 * Creates a chunk download handle (including the cURL handle) and adds it to
 * the meta-chunk download handle for processing.
 * @param mc_handle The meta-chunk download handle.
 * @param url The chunk URI
 * @return A chunk download handle.
 */
	void http_get_add_chunk(struct http_get_s *mc_handle, gchar * url);


/**
 * Fetches an EC meta-chunk range.
 *
 * Loops until the meta-chunk is downloaded, and returns the data.
 *
 * @param mc The meta-chunk download handle.
 * @param result A pointer to a non allocated GBytes buffer.
 * @return The wanted range of decoded original data.
 */
	GError *http_get_process_metachunk_range(struct http_get_s *mc,
			GBytes ** result);

	int http_get_ec_get_fragment_size(int ec_handle, int data_len);

	struct http_get_range *http_get_range_convert(const struct
			oio_sds_dl_range_s *rng);

	void http_get_clean_mc_handle(struct http_get_s *mc);

#ifdef __cplusplus
}
#endif
#endif							/*OIO_SDS__sdk__http_put_h */
