#ifndef __PLUGIN_HOLDER_H__
#define __PLUGIN_HOLDER_H__

gint plugin_holder_close_all (GError **err);

gint plugin_holder_init_all (GError **err);

gint plugin_holder_reload_all (GError **err);

gint plugin_holder_keep (GModule *mod, GHashTable *params, GError **err);

gint plugin_holder_update_config (GModule *mod, GHashTable *params, GError **err);

#endif /*__PLUGIN_HOLDER_H__*/
