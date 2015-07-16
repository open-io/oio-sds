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

## oio-bootstrap.py

## zk-bootstrap.py

## zk-reset.py

