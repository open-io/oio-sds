/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include "metautils.h"

gchar*
get_rawx_location(service_info_t* rawx)
{
	const gchar *loc = service_info_get_rawx_location(rawx, NULL);
	return loc && *loc ? g_strdup(loc) : NULL;
}

guint
distance_between_location(const gchar *loc1, const gchar *loc2)
{
	/* The arrays of tokens. */
	gchar **split_loc1, **split_loc2;
	/* Used to iterate over the arrays of tokens. */
	gchar **iter_tok1, **iter_tok2;
	/* The current tokens. */
	gchar *cur_tok1, *cur_tok2;
	/* Stores the greatest number of tokens in both location names. */
	guint num_tok = 0U;
	/* Number of the current token. */
	guint cur_iter = 0U;
	/* TRUE if a different token was found. */
	gboolean found_diff = FALSE;
	/* Distance between 2 tokens. */
	guint token_dist;

	if ((!loc1 || !*loc1) && (!loc2 || !*loc2))
		return 1U;

	split_loc1 = g_strsplit(loc1, ".", 0);
	split_loc2 = g_strsplit(loc2, ".", 0);

	iter_tok1 = split_loc1;
	iter_tok2 = split_loc2;

	cur_tok2 = *iter_tok2;

	while ((cur_tok1 = *iter_tok1++)) {
		num_tok++;
		if (cur_tok2 && (cur_tok2 = *iter_tok2++) && !found_diff) {
			cur_iter++;
			/* if both tokens are equal, continue */
			/* else set the found_diff flag to TRUE, keep the value of cur_iter and continue to set num_tok */
			if (g_strcmp0(cur_tok1, cur_tok2))
				found_diff = TRUE;
		}
	}

	/* if loc2 has more tokens than loc1, increase num_tok to this value */
	if (cur_tok2) {
		while (*iter_tok2++)
			num_tok++;
	}

	/* Frees the arrays of tokens. */
	g_strfreev(split_loc1);
	g_strfreev(split_loc2);

	token_dist = num_tok - cur_iter + 1;

	/* If the token distance is 1 and the last tokens are equal (ie both locations are equal) -> return 0. */
	/* If the token distance is 1 and the last tokens are different -> return 1. */
	/* If the token distance is > 1, then return 2^(token_dist). */
	return token_dist > 1U ? 1U << (token_dist - 1U) : (found_diff ? 1U : 0U);
}

guint
distance_between_services(struct service_info_s *s0, struct service_info_s *s1)
{
	return distance_between_location(
			service_info_get_rawx_location(s0, ""),
			service_info_get_rawx_location(s1, ""));
}

