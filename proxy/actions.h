/*
OpenIO SDS proxy
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__proxy__actions_h
# define OIO_SDS__proxy__actions_h 1

struct req_args_s;

enum http_rc_e action_forward (struct req_args_s *args);
enum http_rc_e action_forward_stats (struct req_args_s *args);

enum http_rc_e action_cache_status (struct req_args_s *args);
enum http_rc_e action_cache_flush_local (struct req_args_s *args);
enum http_rc_e action_cache_flush_high (struct req_args_s *args);
enum http_rc_e action_cache_flush_low (struct req_args_s *args);
enum http_rc_e action_cache_set_ttl_low (struct req_args_s *args);
enum http_rc_e action_cache_set_ttl_high (struct req_args_s *args);
enum http_rc_e action_cache_set_max_low (struct req_args_s *args);
enum http_rc_e action_cache_set_max_high (struct req_args_s *args);

enum http_rc_e action_lb_choose (struct req_args_s *args);
enum http_rc_e action_lb_poll (struct req_args_s *args);

enum http_rc_e action_local_list (struct req_args_s *args);

enum http_rc_e action_conscience_info (struct req_args_s *args);
enum http_rc_e action_conscience_list (struct req_args_s *args);
enum http_rc_e action_conscience_register (struct req_args_s *args);
enum http_rc_e action_conscience_deregister (struct req_args_s *args);
enum http_rc_e action_conscience_flush (struct req_args_s *args);
enum http_rc_e action_conscience_lock (struct req_args_s *args);
enum http_rc_e action_conscience_unlock (struct req_args_s *args);

enum http_rc_e action_ref_create (struct req_args_s *args);
enum http_rc_e action_ref_destroy (struct req_args_s *args);
enum http_rc_e action_ref_show (struct req_args_s *args);
enum http_rc_e action_ref_prop_get (struct req_args_s *args);
enum http_rc_e action_ref_prop_set (struct req_args_s *args);
enum http_rc_e action_ref_prop_del (struct req_args_s *args);
enum http_rc_e action_ref_link (struct req_args_s *args);
enum http_rc_e action_ref_relink (struct req_args_s *args);
enum http_rc_e action_ref_unlink (struct req_args_s *args);
enum http_rc_e action_ref_force (struct req_args_s *args);
enum http_rc_e action_ref_renew (struct req_args_s *args);

enum http_rc_e action_container_create (struct req_args_s *args);
enum http_rc_e action_container_destroy (struct req_args_s *args);
enum http_rc_e action_container_show (struct req_args_s *args);
enum http_rc_e action_container_list (struct req_args_s *args);
enum http_rc_e action_container_prop_get (struct req_args_s *args);
enum http_rc_e action_container_prop_set (struct req_args_s *args);
enum http_rc_e action_container_prop_del (struct req_args_s *args);
enum http_rc_e action_container_touch (struct req_args_s *args);
enum http_rc_e action_container_dedup (struct req_args_s *args);
enum http_rc_e action_container_purge (struct req_args_s *args);
enum http_rc_e action_container_flush (struct req_args_s *args);
enum http_rc_e action_container_raw_insert (struct req_args_s *args);
enum http_rc_e action_container_raw_update (struct req_args_s *args);
enum http_rc_e action_container_raw_delete (struct req_args_s *args);

enum http_rc_e action_content_put (struct req_args_s *args);
enum http_rc_e action_content_delete (struct req_args_s *args);
enum http_rc_e action_content_show (struct req_args_s *args);
enum http_rc_e action_content_prepare (struct req_args_s *args);
enum http_rc_e action_content_prop_get (struct req_args_s *args);
enum http_rc_e action_content_prop_set (struct req_args_s *args);
enum http_rc_e action_content_prop_del (struct req_args_s *args);
enum http_rc_e action_content_touch (struct req_args_s *args);
enum http_rc_e action_content_spare (struct req_args_s *args);
enum http_rc_e action_content_copy (struct req_args_s *args);
enum http_rc_e action_content_link (struct req_args_s *args);

// Admin on SQLX bases

enum http_rc_e action_admin_ping (struct req_args_s *args);
enum http_rc_e action_admin_status (struct req_args_s *args);
enum http_rc_e action_admin_info (struct req_args_s *args);
enum http_rc_e action_admin_drop_cache (struct req_args_s *args);
enum http_rc_e action_admin_sync (struct req_args_s *args);
enum http_rc_e action_admin_leave (struct req_args_s *args);
enum http_rc_e action_admin_debug (struct req_args_s *args);
enum http_rc_e action_admin_copy (struct req_args_s *args);
enum http_rc_e action_admin_prop_get (struct req_args_s *args);
enum http_rc_e action_admin_prop_set (struct req_args_s *args);
enum http_rc_e action_admin_prop_del (struct req_args_s *args);
enum http_rc_e action_admin_freeze (struct req_args_s *args);
enum http_rc_e action_admin_enable (struct req_args_s *args);
enum http_rc_e action_admin_disable (struct req_args_s *args);

// Administration requests other than SQLX

enum http_rc_e action_admin_meta0_list(struct req_args_s *args);
enum http_rc_e action_admin_meta0_force(struct req_args_s *args);

// Deprecated action handlers with no equivalent yet in recent routes

enum http_rc_e action_m2_container_stgpol (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_setvers (struct req_args_s *args, json_object *jargs);

enum http_rc_e action_sqlx_propget (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_propset (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_propdel (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_copyto (struct req_args_s *args, json_object *jargs);

#endif /*OIO_SDS__proxy__actions_h*/
