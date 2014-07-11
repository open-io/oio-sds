#ifndef GS_CRAWLER_LOCK__H
# define GS_CRAWLER_LOCK__H 1

int volume_lock_get(const gchar *path, const gchar *xattr_name);

void volume_lock_release(const gchar *path, const gchar *xattr_name);

int volume_lock_set(const gchar *path, const gchar *xattr_name);

#endif /* GS_CRAWLER_LOCK__H */
