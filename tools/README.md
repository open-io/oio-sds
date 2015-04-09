# Miscellaneous tools

## oio-reset.sh

Generate a development envionment entirely located in the caller's home directory.

The script accepts the following options (with the default values):
  * -D "3" : how many replicas are necessary for a directory shard (meta1 base).
  * -B "3" : how many replicas are necessary for a container (meta2 base).
  * -S "SINGLE" : sets the default storage policy propagated by the conscience to all the meta2 services.
  * -V "1" : sets the maximum number of versions for a content in a container.
  * -N "NS" : tells the Namespace to work with.
  * -I "127.0.0.1" : set the default IP to bind services to.

## oio/sds/admin-flask.py

This flask provides HTTP requests handlers for "upper-than-low" level of features.

### GET /v1.0/admin/info/<ns>/<ref>
Replaces the logic behind "oio info $NS/$REF"

### GET /v1.0/admin/info/<ns>/<ref>/<path>
Replaces the logic behind "oio info $NS/$REF/$PATH"

### POST /v1.0/admin/container/<ns>/<ref>
Replaces the logic behind "oio put $NS/$REF"

### MOVE /v1.0/admin/container/<ns>/<ref>
Replaces the logic behind "oio-meta2-mover"

### MOVE /v1.0/admin/chunk/<ns>/<ref>/<path>
Replaces the logic behind "oio-rawx-mover"

The URL identifies the content the chunk belongs to, and the current chunks locations is expected in the body, encoded in JSON.
A new location will be polled, and replaced in the meta2.

