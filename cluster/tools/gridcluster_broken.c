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

struct grid_element_s {
};

static gboolean
break_something(const gchar *grid_url)
{
	gchar buf_url[2048];
	gchar **tokens_url;

	g_strlcpy(buf_url, grid_url, sizeof(buf_url));

	tokens_url = g_strsplit(grid_url, "/", 3);
}

int
main(int argc, char ** args)
{
}

