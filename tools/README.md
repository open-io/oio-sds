# Miscellaneous tools

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

