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

#include <string.h>
#include <metautils/lib/metautils.h>
#include <server/internals.h>
#include "path_parser.h"

/* Allocates a node an initaite it with the given word and variable. */
static struct trie_node_s * _node_init (const struct trie_node_s*,
		const gchar *word, const gchar *variable);

/* Clean the node and all its children (recursively) */
static void _node_free (struct trie_node_s *);

/* Allocates an empty array */
static struct trie_node_s ** _nodev_empty (void);

/* clean the array */
static void _nodev_free (struct trie_node_s **);

/* Search the array for an element with the same word or the same variable */
static struct trie_node_s * _nodev_lookup (struct trie_node_s **,
		const gchar *, const gchar *);

/* appends to the node array */
struct trie_node_s ** _nodev_append (struct trie_node_s **, struct trie_node_s *);

/* Fills the tree */
static struct trie_node_s ** _trie_insert (const struct trie_node_s *,
		struct trie_node_s **, gchar **, const char*, gpointer);

/* Recursively run the tree */
static GSList * _trie_explore (struct trie_node_s **, gchar **,
		const struct path_matching_s *);

static struct path_matching_s * _match_dup (const struct path_matching_s *m0);

static void _match_free (struct path_matching_s *);

/* ------------------------------------------------------------------------- */

struct path_parser_s *
path_parser_init (void)
{
	struct path_parser_s *self = g_try_malloc0 (sizeof(*self));
	self->roots = _nodev_empty ();
	return self;
}

void
path_parser_clean (struct path_parser_s *self)
{
	if (!self)
		return;
	_nodev_free (self->roots);
	g_free (self);
}

struct path_matching_s **
path_parser_match (struct path_parser_s *self, gchar **tokens)
{
	struct path_matching_s nomatch = {NULL,NULL};
	GSList *lmatch = _trie_explore (self->roots, tokens, &nomatch);

	struct path_matching_s **p, **result;
	p = result = g_try_malloc0 ((1 + g_slist_length(lmatch)) * sizeof (struct path_matching_s*));
	for (GSList *l=lmatch; l ;l=l->next)
		(*p++) = l->data;
	g_slist_free (lmatch);
	return result;
}

void
path_parser_configure (struct path_parser_s *self, const char *descr, void *u)
{
	EXTRA_ASSERT (self != NULL);
	EXTRA_ASSERT (descr != NULL);
	gchar **tokens = g_strsplit (descr, "/", -1);
	self->roots = _trie_insert (NULL, self->roots, tokens, descr, u);
	g_strfreev (tokens);
}

void
path_matching_cleanv (struct path_matching_s **tab)
{
	if (!tab)
		return;
	for (struct path_matching_s **p = tab; *p ;++p)
		_match_free (*p);
	g_free (tab);
}

const gchar *
path_matching_get_variable (struct path_matching_s *self, const char *name)
{
	EXTRA_ASSERT (self != NULL);
	EXTRA_ASSERT (name != NULL);

	gsize l = strlen (name);
	gchar *key = g_alloca (l+2);
	memcpy(key, name, l);
	key[l] = '=';
	key[l+1] = 0;

	for (gchar **p = self->vars; *p ;++p) {
		if (g_str_has_prefix (*p, key))
			return (*p) + (l+1);
	}

	return NULL;
}

/* ------------------------------------------------------------------------- */

struct path_matching_s *
_match_dup (const struct path_matching_s *m0)
{
	struct path_matching_s *m = SLICE_NEW (struct path_matching_s);
	m->last = m0->last;
	m->vars = m0->vars ? g_strdupv (m0->vars) : g_try_malloc0 (sizeof(gchar*));
	return m;
}

void
_match_free (struct path_matching_s *m)
{
	if (m->vars) g_strfreev (m->vars);
	SLICE_FREE (struct path_matching_s, m);
}

struct trie_node_s *
_node_init (const struct trie_node_s *parent, const gchar *word, const gchar *var)
{
	struct trie_node_s *n = g_try_malloc (sizeof(struct trie_node_s));
	n->parent = parent;
	n->next = _nodev_empty ();
	n->word = word ? g_strdup (word) : NULL;
	n->var = var ? g_strdup (var) : NULL;
	n->u = NULL;
	return n;
}

void
_node_free (struct trie_node_s *n)
{
	if (!n)
		return;
	if (n->word)
		g_free (n->word);
	if (n->var)
		g_free (n->var);
	_nodev_free (n->next);
	g_free (n);
}

struct trie_node_s **
_nodev_empty (void)
{
	return g_try_malloc0 (4 * sizeof(struct trie_node_s*));
}

void
_nodev_free (struct trie_node_s **tab)
{
	if (!tab)
		return;
	for (struct trie_node_s **p = tab; *p ;++p) {
		_node_free (*p);
		*p = NULL;
	}
	g_free (tab);
}

static gsize
_nodev_length (struct trie_node_s **tab)
{
	gsize count = 0;
	while (*(tab++))
		count ++;
	return count;
}

struct trie_node_s **
_nodev_append (struct trie_node_s **tab, struct trie_node_s *n)
{
	gsize l = _nodev_length (tab);
	tab = g_try_realloc (tab, (l+2) * sizeof (struct trie_node_s*));
	tab[l] = n;
	tab[l+1] = NULL;
	return tab;
}

struct trie_node_s *
_nodev_lookup (struct trie_node_s **tab, const gchar *word, const gchar *var)
{
	EXTRA_ASSERT (tab != NULL);
	EXTRA_ASSERT ((word != NULL) ^ (var != NULL));

	for (; *tab ;++tab) {
		if (word && (*tab)->word && !strcmp (word, (*tab)->word))
			return *tab;
		if (var && (*tab)->var && !strcmp (var, (*tab)->var))
			return *tab;
	}
	return NULL;
}

#define P PROXYD_PREFIX"/$NS/"

static gchar *
_stat_name (const char *prefix, const char *tail, gchar *d, gsize dlen)
{
	if (g_str_has_prefix(tail, P))
		dlen = g_snprintf (d, dlen, "%s.%s", prefix, tail+sizeof(P)-1);
	else if (g_str_has_prefix(tail, PROXYD_PREFIX))
		dlen = g_snprintf (d, dlen, "%s.%s", prefix, tail+sizeof(PROXYD_PREFIX)-1);
	else
		dlen = g_snprintf (d, dlen, "%s.%s", prefix, tail);

	/* replace ugly characters by '_' */
	for (int i=strlen (prefix)+1; d[i] ;++i) {
		if (!g_ascii_isalnum (d[i]))
			d[i]='_';
	}

	gchar *s;
	/* agregate subsequent '_' */
	while (NULL != (s = g_strrstr_len(d, dlen, "__"))) {
		for (;*s;++s)
			*s = *(s+1);
	}

	return d;
}

struct trie_node_s **
_trie_insert (const struct trie_node_s *parent, struct trie_node_s **tab,
		gchar **words, const char *descr, gpointer u)
{
	EXTRA_ASSERT (tab != NULL);
	EXTRA_ASSERT (words != NULL);
	EXTRA_ASSERT (*words != NULL);

	const gchar *word = NULL, *var = NULL;
	if (**words == '$')
		var = (*words) + 1;
	else
		word = *words;

	// The word didn't exist yet, create it
	struct trie_node_s *n = _nodev_lookup (tab, word, var);
	if (!n) {
		n = _node_init (parent, word, var);
		tab = _nodev_append (tab, n);
	}

	// Then recurse on the next words, or mark the node as final.
	if (*(words+1))
		n->next = _trie_insert (n, n->next, words+1, descr, u);
	else {
		gchar tmp[512];
		n->u = u;
		n->gq_count = g_quark_from_string (
				_stat_name(OIO_STAT_PREFIX_REQ, descr, tmp, sizeof(tmp)));
		n->gq_time = g_quark_from_string (
				_stat_name(OIO_STAT_PREFIX_TIME, descr, tmp, sizeof(tmp)));
	}

	return tab;
}

GSList *
_trie_explore (struct trie_node_s **tab, gchar **needles,
		const struct path_matching_s *current_match)
{
	GSList *matches = NULL;

	void step (struct path_matching_s *m) {
		if (!needles[1]) { // potential final match
			if (!(*tab)->u) // we matched nothing
				_match_free (m);
			else // final match found
				matches = g_slist_prepend (matches, m);
		} else { // only a partial match, so we recurse
			GSList *local_matches = _trie_explore ((*tab)->next, needles+1, m);
			_match_free (m);
			if (local_matches) {
				/* XXX(jfs): the order matters! */
				matches = g_slist_concat (matches, local_matches);
			}
		}
	}

	EXTRA_ASSERT (needles && *needles);

	for (; *tab ;++tab) {
		if ((*tab)->word) { // Explicit word
			if (0 != strcmp (*needles, (*tab)->word))
				continue;
			struct path_matching_s *m = _match_dup (current_match);
			m->last = *tab;
			step (m);
		} else { // Wildcard
			struct path_matching_s *m = _match_dup (current_match);
			m->last = *tab;
			m->vars = oio_strv_append (m->vars, g_strdup_printf("%s=%s", (*tab)->var, *needles));
			step (m);
		}
	}

	return matches;
}

static void
_run (void (*hook) (const struct trie_node_s *), struct trie_node_s **p)
{
	for (; *p ;++p) {
		if ((*p)->u) hook (*p);
		if ((*p)->next) _run (hook, (*p)->next);
	}
}

void
path_parser_foreach (struct path_parser_s *self,
		void (*hook) (const struct trie_node_s *))
{
	if (self->roots) _run (hook, self->roots);
}

