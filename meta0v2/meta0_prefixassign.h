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

/**
 *  * @file meta0_prefixassign.h
 *   */

#ifndef GRID__META0_PREFIXASSIGN__H
# define GRID__META0_PREFIXASSIGN__H 1

/**
 *  * @addtogroup meta0v2_prefixassign
 *   * @{
 *    */

struct meta0_assign_meta1_s;

GError* meta0_assign_prefix_to_meta1(struct meta0_backend_s *m0, gchar *ns_name, gboolean nocheck);

GError* meta0_assign_disable_meta1(struct meta0_backend_s *m0, gchar *ns_name,char **m1urls, gboolean nocheck);

GError* meta0_assign_fill(struct meta0_backend_s *m0, gchar *ns_name, guint replicas);
/** @} */

#endif /* GRID__META0_PREFIXASSIGN__H */
