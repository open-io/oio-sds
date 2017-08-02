/*
OpenIO SDS proxy
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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
	GQuark gq_count;
	GQuark gq_time;
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

/* Run the parsing logic. Returns a NULL pointer array of matching
 * structures. The return has to be freed with path_matching_cleanv(). */
struct path_matching_s ** path_parser_match (struct path_parser_s *self,
		gchar **tokens);

void path_parser_foreach (struct path_parser_s *self,
		void (*hook) (const struct trie_node_s *n));

/* Returns the variable captured during the matching process. */
const gchar * path_matching_get_variable (struct path_matching_s *self,
		const char *name);

void path_matching_cleanv (struct path_matching_s **tab);

#endif /*OIO_SDS__proxy__path_parser_h*/
