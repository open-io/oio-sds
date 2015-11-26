/*
OpenIO SDS proxy
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__proxy__path_parser_h
# define OIO_SDS__proxy__path_parser_h 1

# include <glib.h>

struct path_matching_s
{
	const struct trie_node_s *last;
	gchar **vars;
};

struct trie_node_s
{
	const struct trie_node_s *parent;
	struct trie_node_s **next;
	gchar *word;
	gchar *var;
	gpointer u;
};

struct path_parser_s
{
	struct trie_node_s **roots;
};

/* Creates a new parser */
struct path_parser_s * path_parser_init (void);

/* Destroys a new parser. Be carefull to never access a matching from
 * this parser after this operation. */
void path_parser_clean (struct path_parser_s *self);

/* Associates <udata> to the description <descr> in the parser <self>.
 * If any data was already associated to <descr>, it is forgotten. */
void path_parser_configure (struct path_parser_s *self,
		const char *descr, void *udata);

/* Dumps a JSON description of the parser's guts. */
GString * path_parser_debug (GString *out, struct path_parser_s *self);

/* Run the parsing logic. Returns a NULL pointer array of matching
 * structures. The return has to be freed with path_matching_cleanv(). */
struct path_matching_s ** path_parser_match (struct path_parser_s *self,
		gchar **tokens);

/* Returns a copy of the description corresponding to the given matching. */
gchar * path_matching_get_path (struct path_matching_s *self);

/* Returns the variable captured during the matching process. */
const gchar * path_matching_get_variable (struct path_matching_s *self,
		const char *name);

/* Returns the arbitrary pointer associated with the description matched. */
gpointer path_matching_get_udata (struct path_matching_s *self);

/* Fills <out> with a JSON representation of <tab> */
GString * path_matching_debugv (GString *out, struct path_matching_s **tab);

/* Fills <out> with a JSON representation of <self> */
GString * path_matching_debug (GString *out, struct path_matching_s *self);

void path_matching_cleanv (struct path_matching_s **tab);

#endif /*OIO_SDS__proxy__path_parser_h*/
