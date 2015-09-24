#ifndef OIO_SDS__core__internals_h
# define OIO_SDS__core__internals_h 1

const char * oio_str_autocontainer_hash (const guint8 *bin, gsize len,
		gchar *dst, const struct oio_str_autocontainer_config_s *cfg);

#endif /*OIO_SDS__core__internals_h*/
